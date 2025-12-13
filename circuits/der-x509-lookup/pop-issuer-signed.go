package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/gnark-eudi/common"
)

// CircuitPoPCA proves:
// 1. I have a certificate with a subject public key
// 2. I can sign a challenge with the private key corresponding to that public key
// 3. Certificate signature is verified with the public key of the CA/QTSP(public input)
// 4. Without revealing the certificate or the public key
type CircuitPoPCA struct {
	// ===== PRIVATE INPUTS (prover's secrets) =====

	// The certificate (secret)
	CertBytes  []uints.U8        `gnark:",secret"`
	CertLength frontend.Variable `gnark:",secret"`

	// Position of subject public key in certificate (from off-circuit parsing)
	SubjectPubKeyPos frontend.Variable `gnark:",secret"`

	// The subject public key (secret - must match the subject key in the certificate)
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// Signature on the challenge (secret)
	ChallengeSignatureR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	ChallengeSignatureS emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigR            emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigS            emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// ===== PUBLIC INPUTS (known to verifier) =====
	Challenge []uints.U8                    `gnark:",public"` // Verifier's challenge
	CAPubKeyX emulated.Element[Secp256r1Fp] `gnark:",public"`
	CAPubKeyY emulated.Element[Secp256r1Fp] `gnark:",public"`
}

// Define implements the circuit logic
func (c *CircuitPoPCA) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// ===== STEP 1: Navigate certificate structure to find SubjectPublicKeyInfo =====
	// This proves we're at the SUBJECT's public key, not the issuer's or any other key
	subjectPubKeyPos := NavigateToSubjectPublicKeyInfoInTBS(api, uapi, c.CertBytes[:])

	// ===== STEP 2: Verify claimed position matches the proven position =====
	api.AssertIsEqual(subjectPubKeyPos, c.SubjectPubKeyPos)

	// ===== STEP 3: Extract subject public key from certificate =====
	extractedPubKey := ExtractSubjectPublicKeyFromCert(
		api,
		uapi,
		c.CertBytes[:],
		subjectPubKeyPos, // Use the proven position
	)

	// ===== STEP 4: Verify extracted key matches the claimed public key =====
	// common.CompareBytes(api, extractedPubKey, circuit.SignerPubKeyBytes)
	common.ComparePublicKeys(api, c.SignerPubKeyX, c.SignerPubKeyY, extractedPubKey)

	// ===== STEP 5: Verify signature on challenge =====
	publicKey := ecdsa.PublicKey[Secp256r1Fp, Secp256r1Fr]{
		X: c.SignerPubKeyX,
		Y: c.SignerPubKeyY,
	}

	signature := ecdsa.Signature[Secp256r1Fr]{
		R: c.ChallengeSignatureR,
		S: c.ChallengeSignatureS,
	}

	common.VerifyES256(api, c.Challenge, publicKey, signature)

	// ==== STEP 6: Verify the Certificate Signature ====
	caPublicKey := ecdsa.PublicKey[Secp256r1Fp, Secp256r1Fr]{
		X: c.CAPubKeyX,
		Y: c.CAPubKeyY,
	}

	certSignature := ecdsa.Signature[Secp256r1Fr]{
		R: c.CertSigR,
		S: c.CertSigS,
	}

	common.VerifyES256(api, c.CertBytes, caPublicKey, certSignature)

	// ===== PROOF COMPLETE =====
	// We've proven:
	// 1. We extracted a public key from a certificate at a claimed position
	// 2. We can produce a valid signature under that public key for the challenge
	// 3. Without revealing the certificate or the public key itself

	return nil
}

// ExtractTBSCertificate finds the TBSCertificate SEQUENCE position and length
func ExtractTBSCertificate(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	certBytes []uints.U8,
) (start, length frontend.Variable) {
	// Certificate structure:
	// 30 [outer-len]           ← Outer Certificate SEQUENCE
	//   30 [tbs-len] [content] ← TBSCertificate SEQUENCE (what we want)
	//   30 [sig-alg-len]       ← Signature Algorithm
	//   03 [sig-len]           ← Signature value

	index := frontend.Variable(0)

	// Skip outer Certificate SEQUENCE tag (0x30)
	tag := ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)

	// Skip outer length field
	_, lengthBytes := ReadDERLength(api, uapi, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Now at TBSCertificate SEQUENCE - this is our start position
	tbsStart := index

	// Verify it's a SEQUENCE (0x30)
	tag = ReadByteAt(api, uapi, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)

	// Read TBS content length
	tbsContentLength, tbsLengthBytes := ReadDERLength(api, uapi, certBytes, index)

	// Total TBS length = 1 (tag) + lengthBytes + content
	tbsTotalLength := api.Add(api.Add(1, tbsLengthBytes), tbsContentLength)

	return tbsStart, tbsTotalLength
}

// ExtractBytesRange extracts a range of bytes starting from 'start' with given 'length'
// This is used to extract the TBS certificate bytes for signature verification
func ExtractBytesRange(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	data []uints.U8,
	start frontend.Variable,
	length frontend.Variable,
) []uints.U8 {
	// We need to handle variable-length extraction
	// Since we can't have truly dynamic arrays, we extract up to max TBS size

	maxTBSSize := 1800 // Adjust based on your certificate sizes
	result := make([]uints.U8, maxTBSSize)

	for i := 0; i < maxTBSSize; i++ {
		// Calculate current position
		currentPos := api.Add(start, i)

		// Check if we're still within the desired range
		// isWithinRange := api.IsZero(api.Sub(
		// 	api.Sub(currentPos, start), // offset from start
		// 	length,                     // should be less than length
		// ))
		// This checks if (currentPos - start) < length
		// But we need: i < length
		iVar := frontend.Variable(i)
		isInRange := isLessThan(api, iVar, length)

		// Read byte at current position
		byte := ReadByteAt(api, uapi, data, currentPos)

		// If in range, use the byte; otherwise use 0
		result[i].Val = api.Select(isInRange, byte.Val, 0)
	}

	return result
}

// isLessThan checks if a < b (both frontend.Variable)
// This is a helper for range checking
func isLessThan(api frontend.API, a, b frontend.Variable) frontend.Variable {
	// a < b is equivalent to: (b - a - 1) has no underflow
	// We check this by verifying the difference is non-negative
	diff := api.Sub(b, a)

	// If diff > 0, then a < b
	isZero := api.IsZero(diff)
	return api.Sub(1, isZero) // Return 1 if not zero (i.e., a < b)
}
