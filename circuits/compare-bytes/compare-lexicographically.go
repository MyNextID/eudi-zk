package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitLex struct {
	// Reference string
	StringReferenceBytes []uints.U8 `gnark:",secret"`
	// String that appears before the reference string
	StringSmallerBytes []uints.U8 `gnark:",secret"`
	// String that appears after the reference string
	StringGreaterBytes []uints.U8 `gnark:",secret"`
	// Same string as the reference
	StringEqualBytes []uints.U8 `gnark:",secret"`

	Positive frontend.Variable `gnark:",secret"`
	Negative frontend.Variable `gnark:",secret"`
	Zero     frontend.Variable `gnark:",secret"`
}

func (c *CircuitLex) Define(api frontend.API) error {

	r, _ := common.IsSmaller(api, c.StringSmallerBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(1))

	r, _ = common.IsSmaller(api, c.StringGreaterBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(0))

	r, _ = common.IsSmaller(api, c.StringEqualBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(0))

	r, _ = common.IsGreater(api, c.StringSmallerBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(0))

	r, _ = common.IsGreater(api, c.StringGreaterBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(1))

	r, _ = common.IsGreater(api, c.StringEqualBytes, c.StringReferenceBytes)
	api.AssertIsEqual(r, frontend.Variable(0))

	return nil
}
