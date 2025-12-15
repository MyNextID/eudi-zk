package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/common"
)

// CircuitPoP proves:
// 1. I have a certificate with a subject public key
// 2. I can sign a challenge with the private key corresponding to that public key
// 3. Without revealing the certificate or the public key
type CircuitPoP struct {
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

	// ===== PUBLIC INPUTS (known to verifier) =====
	Challenge []uints.U8 `gnark:",public"` // Verifier's challenge
}

// Define implements the circuit logic
func (c *CircuitPoP) Define(api frontend.API) error {

	// ===== STEP 1: Navigate certificate structure to find SubjectPublicKeyInfo =====
	// This proves we're at the SUBJECT's public key, not the issuer's or any other key
	subjectPubKeyPos := NavigateToSubjectPublicKeyInfo(api, c.CertBytes[:])

	// ===== STEP 2: Verify claimed position matches the proven position =====
	api.AssertIsEqual(subjectPubKeyPos, c.SubjectPubKeyPos)

	// ===== STEP 3: Extract subject public key from certificate =====
	extractedPubKey := ExtractSubjectPublicKeyFromCert(
		api,
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
	// ===== PROOF COMPLETE =====
	// We've proven:
	// 1. We extracted a public key from a certificate at a claimed position
	// 2. We can produce a valid signature under that public key for the challenge
	// 3. Without revealing the certificate or the public key itself

	return nil
}
