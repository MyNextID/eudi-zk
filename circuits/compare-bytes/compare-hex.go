package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitHex struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	BytesHex []uints.U8 `gnark:",public"`
}

func (c *CircuitHex) Define(api frontend.API) error {

	// decode hex
	bytes, _ := common.DecodeHex(api, c.BytesHex)

	// compare the decoded and provided bytes
	common.AssertIsEqualBytes(api, c.Bytes, bytes)

	return nil
}
