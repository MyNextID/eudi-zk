package verifyjwscert

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/zkcore"
)

// VerifyX509Signature verifies a signature of a DER encoded X.509 certificate
// CertTBSDER is the DER encoded certificate signature payload, aka Certificate To Be Signed (TBS) payload.
func (c *Circuit) VerifyX509Signature(api frontend.API) error {

	messageHash, _ := zkcore.SHA256FiniteLengthSum(api, c.CertTBSDER, c.CertTBSDERSize)

	mHash, err := zkcore.Sha256ToP256Fr(api, messageHash)
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
