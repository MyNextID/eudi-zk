package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/zkcore"
)

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

// CircuitPK defines a circuit that converts public key elements to octet strings
// and asserts equality with the provided octet string representation
type CircuitPK struct {
	// Secret inputs
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	// Public inputs
	SignerPubKeyXBytes []uints.U8 `gnark:",public"`
	SignerPubKeyYBytes []uints.U8 `gnark:",public"`
}

// Define defines the circuit logic
func (c *CircuitPK) Define(api frontend.API) error {

	// public key to bytes
	xBytes := zkcore.EmulatedElementToBytes32(api, c.SignerPubKeyX)
	yBytes := zkcore.EmulatedElementToBytes32(api, c.SignerPubKeyY)

	// Compare the digests byte by byte using the Val() method to access the underlying variable
	zkcore.AssertIsEqualBytes(api, xBytes, c.SignerPubKeyXBytes)
	zkcore.AssertIsEqualBytes(api, yBytes, c.SignerPubKeyYBytes)

	return nil
}
