package ckb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type PubKeyHashCircuit struct {
	// Secret inputs - the actual public key coordinates
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// Public input - the expected hash of the public key as ASCII hex characters
	// This should be 64 bytes, each containing the ASCII value of a hex character
	// For example, the hex string "5d23" should be represented as:
	// [53, 100, 50, 51] (ASCII values of '5', 'd', '2', '3')
	PubKeyHex []uints.U8 `gnark:",public"`
}

func (c *PubKeyHashCircuit) Define(api frontend.API) error {
	// Convert the public key coordinates to bytes using the helper function
	xBytes := c.emulatedElementToBytes32(api, c.SignerPubKeyX)
	yBytes := c.emulatedElementToBytes32(api, c.SignerPubKeyY)

	// Create the uncompressed public key format: 0x04 || X || Y
	// Total: 1 + 32 + 32 = 65 bytes
	pubKeyBytes := make([]uints.U8, 65)

	// First byte is 0x04 (uncompressed point marker)
	pubKeyBytes[0] = uints.U8{Val: 4}

	// Copy X coordinate bytes
	copy(pubKeyBytes[1:33], xBytes)

	// Copy Y coordinate bytes
	copy(pubKeyBytes[33:65], yBytes)

	// Compute SHA256 hash of the public key bytes
	sha256API, err := sha2.New(api)
	if err != nil {
		return err
	}

	sha256API.Write(pubKeyBytes)

	// Hash the 65-byte public key
	digest := sha256API.Sum()

	// Convert digest to hex representation
	hexDigest := make([]uints.U8, 64)

	for i := 0; i < 32; i++ {
		// Get the byte value
		digestByte := digest[i]

		// Split into high and low nibbles using division
		highNibble := api.Div(digestByte.Val, 16)
		lowNibble := api.Sub(digestByte.Val, api.Mul(highNibble, 16))

		// Convert nibbles to hex characters (ASCII values)
		// Use IsZero for comparison instead of Cmp
		// '0' = 48, 'a' = 97
		// For values 0-9: add 48
		// For values 10-15: add 87 (which gives 'a'-'f')

		// Check if nibble < 10 by checking if (nibble - 10) is negative
		// If (10 - nibble) > 0, then nibble < 10
		// highIsLessThan10 := api.IsZero(api.IsZero(api.Sub(10, highNibble)))
		// lowIsLessThan10 := api.IsZero(api.IsZero(api.Sub(10, lowNibble)))

		// Actually, let's use a cleaner approach with subtraction and range checks
		// nibble < 10 means we add 48, otherwise add 87
		// We can compute: 48 + nibble + (nibble >= 10 ? 39 : 0)

		// Simpler: check each nibble value directly
		highChar := nibbleToHex(api, highNibble)
		lowChar := nibbleToHex(api, lowNibble)

		hexDigest[i*2] = uints.U8{Val: highChar}
		hexDigest[i*2+1] = uints.U8{Val: lowChar}
	}

	// api.Println("len(c.PubKeyHex)", len(c.PubKeyHex))

	// Compare the computed hex digest with the provided PubKeyHex
	api.Println("len", len(c.PubKeyHex))
	// if len(c.PubKeyHex) != 64 {
	// 	return errors.New("invalid pub key hex size")
	// }

	for i := 0; i < 64; i++ {
		api.AssertIsEqual(hexDigest[i].Val, c.PubKeyHex[i].Val)
	}

	return nil
}

// nibbleToHex converts a nibble (0-15) to its ASCII hex character
// 0-9 -> '0'-'9' (48-57)
// 10-15 -> 'a'-'f' (97-102)
func nibbleToHex(api frontend.API, nibble frontend.Variable) frontend.Variable {
	// Compute the result for both cases:
	// If nibble < 10: result = 48 + nibble (ASCII '0' + offset)
	// If nibble >= 10: result = 87 + nibble (ASCII 'a' - 10 + offset)

	// Create lookup table for all 16 possible values
	result := frontend.Variable(0)

	// Check each possible nibble value (0-15) and select the correct ASCII value
	for val := 0; val <= 15; val++ {
		isThisValue := api.IsZero(api.Sub(nibble, val))
		var asciiValue int
		if val < 10 {
			asciiValue = 48 + val // '0' through '9'
		} else {
			asciiValue = 87 + val // 'a' through 'f' (97 = 87 + 10)
		}
		// Multiply by isThisValue (0 or 1) and add to result
		result = api.Add(result, api.Mul(isThisValue, asciiValue))
	}

	return result
}

func (c *PubKeyHashCircuit) emulatedElementToBytes32(api frontend.API, elem emulated.Element[Secp256r1Fp]) []uints.U8 {
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
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		byteValue := frontend.Variable(0)

		// Build each byte from 8 bits
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
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

func (c *PubKeyHashCircuit) emulatedElementToBytes32v1(api frontend.API, elem emulated.Element[Secp256r1Fp]) []uints.U8 {
	field, err := emulated.NewField[Secp256r1Fp](api)
	if err != nil {
		panic(err)
	}

	reduced := field.Reduce(&elem)
	bits := field.ToBits(reduced)

	// Ensure we have exactly 256 bits
	if len(bits) < 256 {
		paddedBits := make([]frontend.Variable, 256)
		for i := 0; i < 256-len(bits); i++ {
			paddedBits[i] = 0
		}
		copy(paddedBits[256-len(bits):], bits)
		bits = paddedBits
	} else if len(bits) > 256 {
		bits = bits[len(bits)-256:]
	}

	bytes := make([]uints.U8, 32)

	// FIX: Reverse bit indexing for big-endian bytes
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		byteValue := frontend.Variable(0)

		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			// Read bits in reverse order (from MSB to LSB in the bits array)
			// Byte 0 should contain bits [255:248]
			// Byte 31 should contain bits [7:0]
			globalBitIdx := 255 - (byteIdx*8 + bitIdx)

			byteValue = api.Add(
				api.Mul(byteValue, 2),
				bits[globalBitIdx],
			)
		}

		bytes[byteIdx] = uints.U8{Val: byteValue}
	}

	return bytes
}
