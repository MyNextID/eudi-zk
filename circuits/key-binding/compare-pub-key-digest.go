package ckb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type PubKeyHashCircuit struct {
	// Secret inputs - the actual public key coordinates
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// Public input - the expected hash of the public key as ASCII hex characters
	PubKeyHex []uints.U8 `gnark:",public"`
}

func (c *PubKeyHashCircuit) Define(api frontend.API) error {
	// Convert the public key coordinates to bytes using the helper function
	xBytes := common.EmulatedElementToBytes32(api, c.SignerPubKeyX)
	yBytes := common.EmulatedElementToBytes32(api, c.SignerPubKeyY)

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

	for i := range 32 {
		// Get the byte value
		digestByte := digest[i]

		// Split into high and low nibbles using division
		highNibble := api.Div(digestByte.Val, 16)
		lowNibble := api.Sub(digestByte.Val, api.Mul(highNibble, 16))

		// check each nibble value
		highChar := nibbleToHex(api, highNibble)
		lowChar := nibbleToHex(api, lowNibble)

		hexDigest[i*2] = uints.U8{Val: highChar}
		hexDigest[i*2+1] = uints.U8{Val: lowChar}
	}

	for i := range 64 {
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
