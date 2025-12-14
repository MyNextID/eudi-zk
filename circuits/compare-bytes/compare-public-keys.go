package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

type CircuitPK struct {
	// Secret inputs
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`
	// Public inputs
	SignerPubKeyXBytes []uints.U8 `gnark:",public"`
	SignerPubKeyYBytes []uints.U8 `gnark:",public"`
}

func (c *CircuitPK) Define(api frontend.API) error {

	// public key to bytes
	xBytes := EmulatedElementToBytes32(api, c.SignerPubKeyX)
	yBytes := EmulatedElementToBytes32(api, c.SignerPubKeyY)

	// Compare the digests byte by byte using the Val() method to access the underlying variable
	common.CompareBytes(api, xBytes, c.SignerPubKeyXBytes)
	common.CompareBytes(api, yBytes, c.SignerPubKeyYBytes)

	return nil
}

func EmulatedElementToBytes32(api frontend.API, elem emulated.Element[Secp256r1Fp]) []uints.U8 {
	field, err := emulated.NewField[Secp256r1Fp](api)
	if err != nil {
		panic(err)
	}

	reduced := field.Reduce(&elem)
	bits := field.ToBits(reduced)

	// ToBits returns LSB-first (little-endian bit order)
	// We need 256 bits exactly
	if len(bits) > 256 {
		bits = bits[:256]
	}

	// Pad with zeros at the end if needed (these are high-order bits)
	if len(bits) < 256 {
		padded := make([]frontend.Variable, 256)
		copy(padded, bits)
		for i := len(bits); i < 256; i++ {
			padded[i] = 0
		}
		bits = padded
	}

	bytes := make([]uints.U8, 32)

	// Convert LSB-first bits to big-endian bytes
	// Byte 0 (most significant) contains bits [255:248]
	// Byte 31 (least significant) contains bits [7:0]
	for byteIdx := range 32 {
		byteValue := frontend.Variable(0)

		// Build each byte from 8 bits
		for bitIdx := range 8 {
			// For big-endian bytes from LSB-first bits:
			// Byte 0 needs bits 255,254,253,...,248
			// Byte 31 needs bits 7,6,5,...,0
			bitPosition := (31-byteIdx)*8 + (7 - bitIdx)

			// Build byte: MSB first
			byteValue = api.Add(
				api.Mul(byteValue, 2),
				bits[bitPosition],
			)
		}

		bytes[byteIdx] = uints.U8{Val: byteValue}
	}

	return bytes
}
