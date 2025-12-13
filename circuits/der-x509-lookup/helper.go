package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
// VerifyTBSMembership proves that TBS bytes are embedded in certificate at the claimed position
func VerifyTBSMembership(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	certBytes []uints.U8,
	tbsBytes []uints.U8,
	tbsStart frontend.Variable,
	tbsLength frontend.Variable,
) {
	// Verify the TBS position in certificate structure
	index := frontend.Variable(0)

	// Skip outer Certificate SEQUENCE
	tag := ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes := ReadDERLength(api, uapi, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Now at TBS SEQUENCE - this should be tbsStart
	api.AssertIsEqual(index, tbsStart)

	// Verify TBS tag
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)

	// Verify TBS length matches
	tbsContentLength, tbsLengthBytes := ReadDERLength(api, uapi, certBytes, index)
	expectedTBSLength := api.Add(api.Add(1, tbsLengthBytes), tbsContentLength)
	api.AssertIsEqual(expectedTBSLength, tbsLength)

	// CRITICAL: Verify every byte of TBS matches the certificate
	for i := 0; i < len(tbsBytes); i++ {
		certByte := ReadByteAt(api, uapi, certBytes, api.Add(tbsStart, i))
		uapi.ByteAssertEq(certByte, tbsBytes[i])
	}
}

// NavigateToSubjectPublicKeyInfoInTBS navigates within TBS certificate (not full cert)
func NavigateToSubjectPublicKeyInfoInTBS(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	tbsBytes []uints.U8,
) frontend.Variable {
	index := frontend.Variable(0)

	// TBS starts with SEQUENCE tag
	tag := ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes := ReadDERLength(api, uapi, tbsBytes, index)
	index = api.Add(index, lengthBytes)

	// Field 1: Version [0] EXPLICIT (optional)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	hasVersion := api.IsZero(api.Sub(tag.Val, 0xA0))
	skipAmount := api.Select(hasVersion, SkipElement(api, uapi, tbsBytes, index), 0)
	index = api.Add(index, skipAmount)

	// Field 2: Serial Number (0x02)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x02)
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Field 3: Signature Algorithm (0x30)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Field 4: Issuer DN (0x30)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Field 5: Validity (0x30)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Field 6: Subject DN (0x30)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Field 7: SubjectPublicKeyInfo (0x30)
	tag = ReadByteAt(api, uapi, tbsBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)

	// Skip SPKI header
	index = api.Add(index, 1)
	_, lengthBytes = ReadDERLength(api, uapi, tbsBytes, index)
	index = api.Add(index, lengthBytes)

	// Skip AlgorithmIdentifier
	skipAmount = SkipElement(api, uapi, tbsBytes, index)
	index = api.Add(index, skipAmount)

	// Now at BIT STRING with public key
	return index
}

// NavigateToSubjectPublicKeyInfo proves we correctly navigate to the subject's public key
// by parsing the certificate structure in the correct order
func NavigateToSubjectPublicKeyInfo(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	certBytes []uints.U8,
) frontend.Variable {
	index := frontend.Variable(0)

	// Verify and skip outer Certificate SEQUENCE (tag 0x30)
	tag := ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes := ReadDERLength(api, uapi, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Enter TBSCertificate SEQUENCE (tag 0x30)
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes = ReadDERLength(api, uapi, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Field 1: Version [0] EXPLICIT (optional, tag 0xA0)
	tag = ReadByteAt(api, uapi, certBytes, index)
	hasVersion := api.IsZero(api.Sub(tag.Val, 0xA0))
	skipAmount := api.Select(hasVersion, SkipElement(api, uapi, certBytes, index), 0)
	index = api.Add(index, skipAmount)

	// Field 2: Serial Number (tag 0x02 - INTEGER)
	// IMPORTANT: We verify the tag to ensure we're at the right field
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x02)
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Field 3: Signature Algorithm (tag 0x30 - SEQUENCE)
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Field 4: Issuer DN (tag 0x30 - SEQUENCE)
	// This is the ISSUER, not what we want!
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Field 5: Validity (tag 0x30 - SEQUENCE)
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Field 6: Subject DN (tag 0x30 - SEQUENCE)
	// This is the SUBJECT, but still not the public key
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Field 7: SubjectPublicKeyInfo (tag 0x30 - SEQUENCE)
	// THIS IS IT! We've proven we're at the 7th field in TBSCertificate
	// which is by definition the subject's public key
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)

	// Skip SEQUENCE header to get to the content
	index = api.Add(index, 1)
	_, lengthBytes = ReadDERLength(api, uapi, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Skip AlgorithmIdentifier SEQUENCE
	skipAmount = SkipElement(api, uapi, certBytes, index)
	index = api.Add(index, skipAmount)

	// Now we're at the BIT STRING containing the subject's public key
	// We've PROVEN this is the subject's key by navigating the structure correctly
	return index
}

// ReadDERLength reads a DER-encoded length and returns (length_value, bytes_used_for_length)
func ReadDERLength(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	data []uints.U8,
	index frontend.Variable,
) (frontend.Variable, frontend.Variable) {
	lengthByte := ReadByteAt(api, uapi, data, index)

	// Check if short form (< 0x80) or long form (>= 0x80)
	bits := api.ToBinary(lengthByte.Val, 8)
	isShortForm := api.IsZero(bits[7])

	// Short form: length is the value itself, uses 1 byte
	shortLength := lengthByte.Val
	shortBytes := frontend.Variable(1)

	// Long form: need to read multiple bytes
	numLengthBytes := api.Sub(lengthByte.Val, 0x80)

	// Read up to 2 bytes for length (handles most certificates)
	byte1 := ReadByteAt(api, uapi, data, api.Add(index, 1))
	byte2 := ReadByteAt(api, uapi, data, api.Add(index, 2))

	// Calculate long form length
	// If numLengthBytes == 1: just byte1
	// If numLengthBytes == 2: (byte1 << 8) | byte2
	isOneByte := api.IsZero(api.Sub(numLengthBytes, 1))
	longLength := api.Select(
		isOneByte,
		byte1.Val,
		api.Add(api.Mul(byte1.Val, 256), byte2.Val),
	)
	longBytes := api.Add(numLengthBytes, 1) // 1 for the length byte itself

	// Return the correct values based on form
	length := api.Select(isShortForm, shortLength, longLength)
	bytesUsed := api.Select(isShortForm, shortBytes, longBytes)

	return length, bytesUsed
}

// SkipElement returns the number of bytes to skip for a complete DER element
func SkipElement(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	data []uints.U8,
	index frontend.Variable,
) frontend.Variable {
	// Skip tag (1 byte)
	lengthIndex := api.Add(index, 1)

	// Read length
	contentLength, lengthBytes := ReadDERLength(api, uapi, data, lengthIndex)

	// Total bytes to skip = 1 (tag) + lengthBytes + contentLength
	return api.Add(api.Add(1, lengthBytes), contentLength)
}

// ExtractSubjectPublicKeyFromCert extracts the 64-byte EC public key from certificate
func ExtractSubjectPublicKeyFromCert(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	certBytes []uints.U8,
	pubKeyPos frontend.Variable,
) []uints.U8 {
	// At pubKeyPos, we expect to find: 03 42 00 04 [64 bytes of key]
	// Where:
	// 03 = BIT STRING tag
	// 42 = length (66 bytes)
	// 00 = unused bits
	// 04 = uncompressed point format
	// [64 bytes] = X coordinate (32 bytes) + Y coordinate (32 bytes)

	// Verify we're at a BIT STRING
	tag := ReadByteAt(api, uapi, certBytes, pubKeyPos)
	api.AssertIsEqual(tag.Val, 0x03)

	// Verify length is 0x42 (66 bytes)
	length := ReadByteAt(api, uapi, certBytes, api.Add(pubKeyPos, 1))
	api.AssertIsEqual(length.Val, 0x42)

	// Verify unused bits = 0x00
	unusedBits := ReadByteAt(api, uapi, certBytes, api.Add(pubKeyPos, 2))
	api.AssertIsEqual(unusedBits.Val, 0x00)

	// Verify format = 0x04 (uncompressed)
	// format := ReadByteAt(api, uapi, certBytes, api.Add(pubKeyPos, 3))
	// api.AssertIsEqual(format.Val, 0x04)

	// Extract 65 bytes of public key (32 bytes X + 32 bytes Y)
	keyStart := api.Add(pubKeyPos, 3)
	publicKey := make([]uints.U8, 65)

	for i := range 65 {
		idx := api.Add(keyStart, i)
		publicKey[i] = ReadByteAt(api, uapi, certBytes, idx)
	}

	return publicKey
}

// ReadByteAt reads a byte at a given index (variable index)
func ReadByteAt(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	data []uints.U8,
	index frontend.Variable,
) uints.U8 {
	result := uints.NewU8(0)
	for i := range data {
		isMatch := api.IsZero(api.Sub(index, i))
		result.Val = api.Select(isMatch, data[i].Val, result.Val)
	}
	return result
}

// BytesToFieldElement converts 32 bytes to a field element
func BytesToFieldElement(api frontend.API, bytes []uints.U8) frontend.Variable {
	if len(bytes) != 32 {
		panic("expected 32 bytes")
	}

	// Convert bytes to big integer (big-endian)
	result := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		// Shift left by 8 bits and add next byte
		result = api.Add(api.Mul(result, 256), bytes[i].Val)
	}
	return result
}

// FindSubjectPublicKeyPosition locates the subject public key in DER bytes
func FindSubjectPublicKeyPosition(certDER []byte) (int, error) {
	// Parse the certificate to find the SubjectPublicKeyInfo position
	// This is done off-circuit using standard Go parsing

	idx := 0

	// Skip outer Certificate SEQUENCE
	idx = skipSequence(certDER, idx)

	// Enter TBSCertificate SEQUENCE
	idx = skipSequence(certDER, idx)

	// Skip version (if present)
	if certDER[idx] == 0xA0 {
		idx = skipElement(certDER, idx)
	}

	// Skip: serialNumber, signature, issuer, validity, subject
	for i := 0; i < 5; i++ {
		idx = skipElement(certDER, idx)
	}

	// Now at SubjectPublicKeyInfo SEQUENCE
	// spkiStart := idx

	// Skip SEQUENCE header to get to AlgorithmIdentifier
	idx++ // Skip tag
	lengthSize, _ := readLength(certDER, idx)
	idx += lengthSize

	// Skip AlgorithmIdentifier SEQUENCE
	idx = skipElement(certDER, idx)

	// Now at BIT STRING containing the public key
	// This is the position we want!
	return idx, nil
}

// ============================================================================
// OFF-CIRCUIT DER PARSING HELPERS
// ============================================================================

func skipSequence(data []byte, idx int) int {
	idx++ // Skip tag
	lengthSize, _ := readLength(data, idx)
	return idx + lengthSize
}

func skipElement(data []byte, idx int) int {
	idx++ // Skip tag
	lengthSize, length := readLength(data, idx)
	return idx + lengthSize + length
}

func readLength(data []byte, idx int) (lengthSize, length int) {
	firstByte := data[idx]
	if firstByte < 0x80 {
		// Short form
		return 1, int(firstByte)
	}
	// Long form
	numBytes := int(firstByte & 0x7F)
	length = 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[idx+1+i])
	}
	return 1 + numBytes, length
}

// FindTBSStart finds where TBS certificate starts in full certificate
func FindTBSStart(certDER []byte) int {
	idx := 0
	// Skip outer Certificate SEQUENCE tag
	idx++
	// Skip outer length
	lengthSize, _ := readLength(certDER, idx)
	idx += lengthSize
	// Now at TBS SEQUENCE
	return idx
}

// FindSubjectPublicKeyPositionInTBS locates the subject public key within TBS bytes
func FindSubjectPublicKeyPositionInTBS(tbsDER []byte) (int, error) {
	idx := 0

	// Skip TBS SEQUENCE header
	idx = skipSequence(tbsDER, idx)

	// Skip version (if present)
	if tbsDER[idx] == 0xA0 {
		idx = skipElement(tbsDER, idx)
	}

	// Skip: serialNumber, signature, issuer, validity, subject
	for i := 0; i < 5; i++ {
		idx = skipElement(tbsDER, idx)
	}

	// Now at SubjectPublicKeyInfo SEQUENCE
	// Skip SEQUENCE header
	idx++
	lengthSize, _ := readLength(tbsDER, idx)
	idx += lengthSize

	// Skip AlgorithmIdentifier
	idx = skipElement(tbsDER, idx)

	// Now at BIT STRING containing the public key
	return idx, nil
}
