package common

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

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
