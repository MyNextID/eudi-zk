package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
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
	CompareBytes(api, c.Bytes, c.PubBytes)

	return nil
}

func CompareBytes(api frontend.API, A, B []uints.U8) {
	lenA := Len(api, A)
	lenB := Len(api, B)

	api.AssertIsEqual(lenA, lenB)

	for i := range A {
		api.AssertIsEqual(A[i].Val, B[i].Val)
	}

}

// Len computes the array size
func Len(api frontend.API, bytes []uints.U8) frontend.Variable {
	length := frontend.Variable(0)
	for range bytes {
		length = api.Add(length, 1)
	}
	return length
}
