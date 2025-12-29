package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/zkcore"
)

// CircuitCompareSubset checks whether the Subset is a subset of the Bytes
type CircuitCompareSubset struct {
	// Secret input
	Bytes         []uints.U8        `gnark:",secret"`
	PositionStart frontend.Variable `gnark:",secret"`

	// Public input
	Subset []uints.U8 `gnark:",public"`
}

// Define implements the ZK circuit logic
func (c *CircuitCompareSubset) Define(api frontend.API) error {

	return zkcore.IsSubset(api, c.Bytes, c.Subset, c.PositionStart)
}
