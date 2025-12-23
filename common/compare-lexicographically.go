package common

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// IsSmaller compares A and B lexicographically
// Returns 1 if A < B, 0 if A >= B
func IsSmaller(api frontend.API, A []uints.U8, B []uints.U8) (frontend.Variable, error) {
	if len(A) != len(B) {
		return nil, errors.New("A and B must be of the same length")
	}

	isSmaller := frontend.Variable(0)
	isDifferent := frontend.Variable(0)

	for i := range A {
		// Compare A[i] with B[i] directly
		cmpResult := api.Cmp(A[i].Val, B[i].Val)

		// Check if different
		diffExists := api.Sub(1, api.IsZero(cmpResult))

		// Check if A[i] < B[i] (cmpResult == -1)
		isLess := api.IsZero(api.Add(cmpResult, 1))

		// Update isSmaller only if we haven't found a difference yet
		isSmaller = api.Select(isDifferent, isSmaller, isLess)

		// Mark that we found a difference
		isDifferent = api.Or(isDifferent, diffExists)
	}

	return isSmaller, nil
}

// IsGreater compares A and B lexicographically
// Returns 1 if A > B, 0 if A <= B
func IsGreater(api frontend.API, A []uints.U8, B []uints.U8) (frontend.Variable, error) {
	if len(A) != len(B) {
		return nil, errors.New("A and B must be of the same length")
	}

	isGreater := frontend.Variable(0)
	isDifferent := frontend.Variable(0)

	for i := range A {
		// Compare A[i] with B[i] directly
		cmpResult := api.Cmp(A[i].Val, B[i].Val)

		// Check if different
		diffExists := api.Sub(1, api.IsZero(cmpResult))

		// Check if A[i] > B[i] (cmpResult == 1)
		isGreater_i := api.IsZero(api.Sub(cmpResult, 1))

		// Update isGreater only if we haven't found a difference yet
		isGreater = api.Select(isDifferent, isGreater, isGreater_i)

		// Mark that we found a difference
		isDifferent = api.Or(isDifferent, diffExists)
	}

	return isGreater, nil
}
