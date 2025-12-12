package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// verifyPubKeyInCertificateOptimized searches for the public key X coordinate in the DER certificate
func (circuit *CircuitJWS) verifyPubKeyInCertificateOptimized(api frontend.API) error {
	/*
		More efficient approach:
		1. Find the 0x04 (uncompressed point indicator) in the certificate
		2. The public key X coordinate should appear immediately after
		3. Search through the entire DER certificate for this pattern

		DER structure for P-256 public key in certificate:
		... BIT STRING ... 0x04 [32 bytes of X] [32 bytes of Y] ...
	*/

	// Convert public key X to bytes (32 bytes for P-256)
	pubKeyXBytes := circuit.emulatedElementToBytes32(api, circuit.SignerPubKeyX)

	derLen := len(circuit.SignerCertDER)
	matchCount := frontend.Variable(0)

	// Search for the pattern: 0x04 followed by 32 bytes matching pubKeyX
	// We need at least 33 bytes: 1 (0x04) + 32 (X coordinate)
	if derLen < 33 {
		// Certificate too short, this will fail the assertion below
		api.AssertIsEqual(matchCount, 1)
		return nil
	}

	// Slide through the DER certificate
	for i := 0; i < derLen-32; i++ { // -32 to ensure we have room for X coordinate
		// Check if current byte is 0x04 (uncompressed point indicator)
		is04 := api.IsZero(api.Sub(circuit.SignerCertDER[i].Val, 0x04))

		// Check if the next 32 bytes match pubKeyX
		var xMatch frontend.Variable
		if i+32 < derLen {
			// Extract the slice for comparison
			certSlice := make([]uints.U8, 32)
			for j := 0; j < 32; j++ {
				certSlice[j] = circuit.SignerCertDER[i+1+j]
			}
			xMatch = circuit.compareBytes(api, certSlice, pubKeyXBytes)
		} else {
			xMatch = 0
		}

		// If both conditions match (0x04 AND X coordinate matches), count it
		thisMatch := api.Mul(is04, xMatch)
		matchCount = api.Add(matchCount, thisMatch)
	}

	// Assert we found at least one match
	// matchCount should be >= 1, so (matchCount == 0) should be false
	isZero := api.IsZero(matchCount)
	api.AssertIsEqual(isZero, 0)
	return nil
}

// compareBytes compares two byte slices and returns 1 if all bytes match, 0 otherwise
func (circuit *CircuitJWS) compareBytes(api frontend.API, a, b []uints.U8) frontend.Variable {
	// Returns 1 if all bytes match, 0 otherwise
	allMatch := frontend.Variable(1)

	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		// Check if bytes are equal
		bytesEqual := api.IsZero(api.Sub(a[i].Val, b[i].Val))
		// Accumulate: if any byte doesn't match, allMatch becomes 0
		allMatch = api.Mul(allMatch, bytesEqual)
	}

	return allMatch
}

// emulatedElementToBytes32 converts an emulated field element to 32 bytes (big-endian)
func (circuit *CircuitJWS) emulatedElementToBytes32(api frontend.API, elem emulated.Element[Secp256r1Fp]) []uints.U8 {
	/*
		Convert emulated field element to 32 bytes for P-256 coordinate
		P-256 field prime is 2^256 - 2^224 + 2^192 + 2^96 - 1
		So coordinates fit in 32 bytes
	*/

	// Create emulated field API
	field, err := emulated.NewField[Secp256r1Fp](api)
	if err != nil {
		panic(err)
	}

	// Reduce the element to canonical form
	reduced := field.Reduce(&elem)

	// Convert to bits (256 bits = 32 bytes)
	bits := field.ToBits(reduced)

	// Group bits into bytes (8 bits per byte)
	// Big-endian: most significant byte first
	bytes := make([]uints.U8, 32)

	for i := 0; i < 32; i++ {
		// Each byte is composed of 8 bits
		// For big-endian, byte 0 contains bits [255:248]
		byteValue := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			bitIndex := 255 - (i*8 + j) // Big-endian bit ordering
			if bitIndex >= 0 && bitIndex < len(bits) {
				// Shift and add: byteValue = byteValue * 2 + bit
				byteValue = api.Add(api.Mul(byteValue, 2), bits[bitIndex])
			}
		}
		// Fix: Pass byteValue directly as frontend.Variable
		bytes[i] = uints.U8{Val: byteValue}
	}

	return bytes
}
