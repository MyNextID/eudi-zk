package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

func (c *JWTCircuit) VerifyX509(api frontend.API) error {
	// Initialize SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Write payload to hasher
	hasher.Write(c.SignerCertDER)

	// Compute SHA256 hash of header.payload
	messageHash := hasher.Sum()

	mHash, err := sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}
	_ = mHash

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.QTSPPubKeyX,
		Y: c.QTSPPubKeyY,
	}
	_ = Pub
	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.CertSigR,
		S: c.CertSigS,
	}

	// // signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}
