package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/gnark-eudi/common"
)

// VerifyX509Signature verifies signature of a DER encoded X.509 certificate
func (c *CircuitJWS) VerifyX509Signature(api frontend.API) error {

	messageHash, _ := common.SHA256(api, c.SignerCertDER)

	mHash, err := sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.QTSPPubKeyX,
		Y: c.QTSPPubKeyY,
	}

	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.CertSigR,
		S: c.CertSigS,
	}

	// // signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}
