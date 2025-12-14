package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Circut checks whether the Subset is a subset of the Bytes
type CircuitCompareSubset struct {
	// Secret input
	Bytes         []uints.U8        `gnark:",secret"`
	PositionStart frontend.Variable `gnark:",secret"`

	// Public input
	Subset []uints.U8 `gnark:",public"`
}

func (c *CircuitCompareSubset) Define(api frontend.API) error {

	return IsSubset(api, c.Bytes, c.Subset, c.PositionStart)
}

func IsSubset(api frontend.API, bytes, subset []uints.U8, positionStart frontend.Variable) error {
	bytesAPI, err := uints.NewBytes(api)
	if err != nil {
		return err
	}

	matchedCount := frontend.Variable(0)

	// For each position in bytes
	for byteIndex := range bytes {
		// Convert byteIndex to frontend.Variable for comparison
		currentPos := frontend.Variable(byteIndex)

		// Check if current position matches positionStart + matchedCount
		isAtMatchPosition := api.IsZero(api.Sub(currentPos, api.Add(positionStart, matchedCount)))

		// Check if we haven't matched all subset bytes yet
		hasMoreToMatch := api.Sub(1, api.IsZero(api.Sub(matchedCount, len(subset))))

		// Only match if at correct position AND haven't finished matching
		isAtMatchPosition = api.Mul(isAtMatchPosition, hasMoreToMatch)

		// For each possible index in subset
		for subsetIndex := range subset {
			// Check if we're comparing the right subset element
			isCorrectSubsetIndex := api.IsZero(api.Sub(matchedCount, subsetIndex))

			// shouldCompare = 1 only when both conditions are true
			shouldCompare := api.Mul(isAtMatchPosition, isCorrectSubsetIndex)

			// Select which byte to compare
			selectedByte := bytesAPI.Select(shouldCompare, bytes[byteIndex], subset[subsetIndex])
			bytesAPI.AssertIsEqual(selectedByte, subset[subsetIndex])
		}

		// Increment counter when we're in the matching range
		matchedCount = api.Add(matchedCount, isAtMatchPosition)
	}

	// Ensure all subset bytes were matched
	api.AssertIsEqual(matchedCount, len(subset))
	return nil
}
