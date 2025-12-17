package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/common"
)

// VerifyJWS combines a protected JWS header with the payload and verifies the
// signature using the provided public keys. Only for ES256
// Assumptions:
// - protected header contains all the non-PII metadata and is a private input
// - payload contains all user info and is a public input
// - selective disclosure of the user info is out of scope of this circuit as we'll address it later
func (c *CircuitJWS) VerifyJWS(api frontend.API) error {
	// Initialize SHA256 hash
	hash, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Concatenate header and payload with a '.' separator (ASCII 46 = 0x2E)
	// format: base64url(header).base64url(payload)
	dotSeparator := uints.NewU8(46)

	// Write header to hasher
	hash.Write(c.JWSProtected)

	// Write dot separator
	hash.Write([]uints.U8{dotSeparator})

	// Write payload to hasher
	hash.Write(c.JWSPayload)

	// Compute SHA256 hash of header.payload
	messageHash := hash.Sum()

	// Convert to P256Fr
	mHash, err := common.Sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.SignerPubKeyX,
		Y: c.SignerPubKeyY,
	}
	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.JWSSigR,
		S: c.JWSSigS,
	}

	// Verify the signature
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}
