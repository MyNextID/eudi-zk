package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

// CircuitSPK proves:
// 1. I have a certificate with a subject public key
// 2. Without revealing the certificate or the public key

type CircuitSPK struct {
	// ===== PRIVATE INPUTS (prover's secrets) =====

	// The certificate (secret)
	CertBytes  []uints.U8        `gnark:",secret"`
	CertLength frontend.Variable `gnark:",secret"`

	// Position of subject public key in certificate (from off-circuit parsing)
	SubjectPubKeyPos frontend.Variable `gnark:",secret"`

	// The subject public key (secret - must match the subject key in the certificate)
	SignerPubKeyBytes []uints.U8 `gnark:",secret"`
}

// Define implements the circuit logic
func (c *CircuitSPK) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// ===== STEP 1: Navigate certificate structure to find SubjectPublicKeyInfo =====
	// This proves we're at the SUBJECT's public key, not the issuer's or any other key
	subjectPubKeyPos := NavigateToSubjectPublicKeyInfo(api, uapi, c.CertBytes[:])

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
	common.CompareBytes(api, extractedPubKey, c.SignerPubKeyBytes)

	return nil
}
