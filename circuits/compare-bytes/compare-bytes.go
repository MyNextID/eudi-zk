package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type Circuit struct {
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	PubBytes []uints.U8 `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {

	// Compare the digests byte by byte using the Val() method to access the underlying variable
	common.CompareBytes(api, c.Bytes, c.PubBytes)

	return nil
}
