package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/zkcore"
)

// CircuitHex decodes a public hex encoded octet string and asserts equality
// with the private octet string
type CircuitHex struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	BytesHex []uints.U8 `gnark:",public"`
}

// Define defines the logic of the circuit
// Step 1: Decode the hex encoded public input
// Step 2: Assert equality between the decoded and secret octet string
func (c *CircuitHex) Define(api frontend.API) error {

	// decode hex
	bytes, _ := zkcore.DecodeHex(api, c.BytesHex)

	// compare the decoded and provided bytes
	zkcore.AssertIsEqualBytes(api, c.Bytes, bytes)

	return nil
}
