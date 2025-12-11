package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

// JWTCircuit defines the ZK circuit for JWT with X.509 certificate verification
/*

Private input

- protected header (we assume all non-PII metadata is here)
- signer's public key
- signed x509 cert of the signer's public key

Public input

- payload
- x509 issuer's public key

Logic:

- reconstruct JWT_message = base64url(header) || '.' || base64url(payload)
- verify that the signers's public key verifies the JWT_message signature
- verify that the QTSP's public key verifies the x509 cert signature
- verify the signer's public key is in the x509 DER cert

*/
type JWTCircuit struct {
	// ===== PRIVATE INPUTS =====
	JWTHeaderB64  []uints.U8                    `gnark:",secret"`
	JWTSigR       emulated.Element[Secp256r1Fr] `gnark:",secret"`
	JWTSigS       emulated.Element[Secp256r1Fr] `gnark:",secret"`
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerCertDER []uints.U8                    `gnark:",secret"`
	CertSigR      emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigS      emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// ===== PUBLIC INPUTS =====
	JWTPayloadPublic []uints.U8                    `gnark:",public"`
	QTSPPubKeyX      emulated.Element[Secp256r1Fp] `gnark:",public"`
	QTSPPubKeyY      emulated.Element[Secp256r1Fp] `gnark:",public"`
}

// Define verifies the ES256 JWT signature in-circuit
func (c *JWTCircuit) Define(api frontend.API) error {
	c.VerifyJWT(api)
	c.VerifyX509(api)
	return c.verifyPubKeyInCertificateOptimized(api)
}
