package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitPKDigest struct {
	// Secret inputs
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	// Public inputs
	SignerPubKeyBytes  []uints.U8 `gnark:",public"`
	SignerPubKeyDigest []uints.U8 `gnark:",public"`
}

func (c *CircuitPKDigest) Define(api frontend.API) error {

	// public key to bytes
	xBytes := EmulatedElementToBytes32(api, c.SignerPubKeyX)
	yBytes := EmulatedElementToBytes32(api, c.SignerPubKeyY)

	// Create the 0x04 prefix for uncompressed point
	prefix := uints.NewU8(4)

	// Concatenate: 0x04 || X || Y (total 65 bytes)
	pubKeyBytes := append(xBytes, yBytes...)
	pubKeyBytes = append([]uints.U8{prefix}, pubKeyBytes...)

	digest, _ := common.SHA256(api, pubKeyBytes)

	common.AssertIsEqualBytes(api, pubKeyBytes, c.SignerPubKeyBytes)
	common.AssertIsEqualBytes(api, digest, c.SignerPubKeyDigest)

	return nil
}
