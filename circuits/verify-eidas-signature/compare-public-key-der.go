package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// X509SubjectPubKeyCircuit extracts the subject public key from a DER-encoded X.509 certificate
type X509SubjectPubKeyCircuit struct {
	CertBytes     []uints.U8 `gnark:",public"`
	SubjectPubKey []uints.U8 `gnark:",public"` // Expected to be 64 bytes for P-256
}

// Define implements the gnark circuit logic
func (circuit *X509SubjectPubKeyCircuit) Define(api frontend.API) error {

	// Extract the subject public key
	extractedKey := ExtractSubjectPublicKey(api, circuit.CertBytes)

	// Verify the extracted key matches the expected output
	// This proves we correctly extracted the subject's public key
	if len(extractedKey) != len(circuit.SubjectPubKey) {
		panic("extracted key length mismatch")
	}

	for i := 0; i < len(extractedKey); i++ {
		api.AssertIsEqual(extractedKey[i].Val, circuit.SubjectPubKey[i].Val)
	}

	return nil
}

// ExtractSubjectPublicKey parses DER-encoded X.509 certificate and extracts subject public key
func ExtractSubjectPublicKey(api frontend.API, certBytes []uints.U8) []uints.U8 {
	// Start parsing from the beginning
	index := frontend.Variable(0)

	// Skip outer Certificate SEQUENCE (tag 0x30)
	index = skipSequence(api, certBytes, index)

	// Enter TBSCertificate SEQUENCE (tag 0x30)
	index = skipSequence(api, certBytes, index)

	// Check if version field exists (tag 0xA0)
	hasVersion := isTagAt(api, certBytes, index, 0xA0)
	index = api.Select(hasVersion, skipElement(api, certBytes, index), index)

	// Field 2: Skip Serial Number (tag 0x02)
	index = skipElement(api, certBytes, index)

	// Field 3: Skip Signature Algorithm (tag 0x30)
	index = skipElement(api, certBytes, index)

	// Field 4: Skip Issuer DN (tag 0x30)
	index = skipElement(api, certBytes, index)

	// Field 5: Skip Validity (tag 0x30)
	index = skipElement(api, certBytes, index)

	// Field 6: Skip Subject DN (tag 0x30)
	index = skipElement(api, certBytes, index)

	// Field 7: SubjectPublicKeyInfo (tag 0x30) - THIS IS IT!
	// Skip SubjectPublicKeyInfo SEQUENCE header
	index = skipSequenceHeader(api, certBytes, index)

	// Skip AlgorithmIdentifier SEQUENCE
	index = skipElement(api, certBytes, index)

	// Now at BIT STRING: 03 [length] 00 04 [key bytes...]
	// Verify we're at a BIT STRING (tag 0x03)
	assertTagAt(api, certBytes, index, 0x03)

	// Read length
	index = incrementIndex(api, index, 1) // Move past tag
	// length := readByteAt(api, certBytes, index)
	index = incrementIndex(api, index, 1) // Move past length

	// Verify unused bits = 0x00
	unusedBits := readByteAt(api, certBytes, index)
	api.AssertIsEqual(unusedBits.Val, 0)
	index = incrementIndex(api, index, 1)

	// Verify uncompressed point format = 0x04
	format := readByteAt(api, certBytes, index)
	api.AssertIsEqual(format.Val, 4)
	index = incrementIndex(api, index, 1)

	// Extract the public key bytes (64 bytes for P-256: 32 bytes X + 32 bytes Y)
	keyLength := 64 // For P-256
	publicKey := make([]uints.U8, keyLength)

	for i := range keyLength {
		publicKey[i] = readByteAt(api, certBytes, index)
		index = incrementIndex(api, index, 1)
	}

	return publicKey
}

// Helper functions for DER parsing in circuit

func skipSequence(api frontend.API, data []uints.U8, index frontend.Variable) frontend.Variable {
	// Verify tag is 0x30 (SEQUENCE)
	assertTagAt(api, data, index, 0x30)
	return skipSequenceHeader(api, data, index)
}

func skipSequenceHeader(api frontend.API, data []uints.U8, index frontend.Variable) frontend.Variable {
	// Move past tag
	index = incrementIndex(api, index, 1)
	// Skip length bytes and return index to content
	return skipLength(api, data, index)
}

func skipElement(api frontend.API, data []uints.U8, index frontend.Variable) frontend.Variable {
	// Skip tag
	index = incrementIndex(api, index, 1)

	// Read length
	lengthByte := readByteAt(api, data, index)
	index = incrementIndex(api, index, 1)

	// Check if short form (< 0x80) or long form
	// Get bit 7 to determine the form
	lengthVal := lengthByte.Val
	bits := api.ToBinary(lengthVal, 8)
	isShortForm := api.IsZero(bits[7]) // bit 7 = 0 means short form

	// Short form: length is the value itself
	shortFormLength := lengthVal

	// Long form: first byte & 0x7F indicates number of length bytes
	// Calculate lengthByte & 0x7F by subtracting 0x80 when in long form
	numLengthBytes := api.Sub(lengthVal, 0x80)

	// Read multi-byte length (simplified for up to 2 bytes)
	lengthByte1 := readByteAt(api, data, index)
	lengthByte2 := readByteAt(api, data, incrementIndex(api, index, 1))

	longFormLength := api.Add(
		api.Mul(lengthByte1.Val, 256),
		lengthByte2.Val,
	)

	// Select based on form
	contentLength := api.Select(isShortForm, shortFormLength, longFormLength)
	lengthBytesUsed := api.Select(isShortForm, 0, numLengthBytes)

	// Skip length bytes and content
	index = incrementIndex(api, index, lengthBytesUsed)
	index = incrementIndex(api, index, contentLength)

	return index
}

func skipLength(api frontend.API, data []uints.U8, index frontend.Variable) frontend.Variable {
	lengthByte := readByteAt(api, data, index)

	// Check if short form by testing if bit 7 is set
	// Short form: bit 7 = 0 (value < 0x80)
	// Long form: bit 7 = 1 (value >= 0x80)
	bits := api.ToBinary(lengthByte.Val, 8)
	isShortForm := api.IsZero(bits[7])

	// Short form: just skip 1 byte
	// Long form: skip 1 + (lengthByte & 0x7F) bytes
	numLengthBytes := api.Sub(lengthByte.Val, 0x80)
	bytesToSkip := api.Select(isShortForm, 1, api.Add(1, numLengthBytes))

	return incrementIndex(api, index, bytesToSkip)
}

func isTagAt(api frontend.API, data []uints.U8, index frontend.Variable, expectedTag int) frontend.Variable {
	actualTag := readByteAt(api, data, index)
	isEqual := api.IsZero(api.Sub(actualTag.Val, expectedTag))
	return isEqual
}

func assertTagAt(api frontend.API, data []uints.U8, index frontend.Variable, expectedTag int) {
	actualTag := readByteAt(api, data, index)
	api.AssertIsEqual(actualTag.Val, expectedTag)
}

func readByteAt(api frontend.API, data []uints.U8, index frontend.Variable) uints.U8 {
	// Use api.Select to pick the byte at the given index
	// This creates a constraint for each possible index position
	result := uints.NewU8(0)

	for i := range data {
		isMatch := api.IsZero(api.Sub(index, i))
		result.Val = api.Select(isMatch, data[i].Val, result.Val)
	}

	return result
}

func incrementIndex(api frontend.API, index frontend.Variable, amount interface{}) frontend.Variable {
	return api.Add(index, amount)
}
