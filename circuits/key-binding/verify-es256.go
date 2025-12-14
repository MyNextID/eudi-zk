package ckb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/common"
)

func (c *JWSCircuit) VerifyJWS(api frontend.API) error {
	// Initialize SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Concatenate header and payload with a '.' separator (ASCII 46 = 0x2E)
	// JWS format: base64url(header).base64url(payload)
	dotSeparator := uints.NewU8(46)

	// Write header to hasher
	hasher.Write(c.JWSHeaderB64)

	// Write dot separator
	hasher.Write([]uints.U8{dotSeparator})

	// Write payload to hasher
	hasher.Write(c.JWSPayloadPublic)

	// Compute SHA256 hash of header.payload
	messageHash := hasher.Sum()

	mHash, err := common.Sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}
	_ = mHash

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.SignerPubKeyX,
		Y: c.SignerPubKeyY,
	}
	_ = Pub
	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.JWSSigR,
		S: c.JWSSigS,
	}

	// // signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}
