// Package ckb defines key-binding verification zk circuit functions
package ckb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

// JWSCircuit defines the ZK circuit for JWS with X.509 certificate verification
/*

 */
type JWSCircuit struct {
	// ===== PRIVATE INPUTS =====
	JWSHeaderB64  []uints.U8                    `gnark:",secret"`
	JWSSigR       emulated.Element[Secp256r1Fr] `gnark:",secret"`
	JWSSigS       emulated.Element[Secp256r1Fr] `gnark:",secret"`
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerCertDER []uints.U8                    `gnark:",secret"`
	CertSigR      emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigS      emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// ===== PUBLIC INPUTS =====
	JWSPayloadPublic []uints.U8                    `gnark:",public"`
	QTSPPubKeyX      emulated.Element[Secp256r1Fp] `gnark:",public"`
	QTSPPubKeyY      emulated.Element[Secp256r1Fp] `gnark:",public"`
}

// Define verifies the ES256 JWS signature in-circuit
func (c *JWSCircuit) Define(api frontend.API) error {
	err := c.VerifyJWS(api)
	if err != nil {
		return err
	}
	err = c.VerifyX509(api)
	if err != nil {
		return err
	}
	return nil
}
