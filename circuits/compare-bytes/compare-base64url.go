package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitB64Url struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	BytesB64 []uints.U8 `gnark:",public"`
}

func (c *CircuitB64Url) Define(api frontend.API) error {
	// Decode base64url
	decodedBytesHex, _ := common.DecodeBase64Url(api, c.BytesB64)

	// Decode hex
	decodedBytes, _ := common.DecodeHex(api, decodedBytesHex)

	_ = decodedBytes
	common.AssertIsEqualBytes(api, c.Bytes, decodedBytes)

	return nil
}
