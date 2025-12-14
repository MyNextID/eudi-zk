package common

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

// Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

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

// Convert lowercase hex characters to bytes
func DecodeHex(api frontend.API, hexChars []uints.U8) ([]uints.U8, error) {
	// Ensure even number of hex characters
	if len(hexChars)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}

	// Initialize Bytes API
	bf, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes API: %w", err)
	}

	bytes := make([]uints.U8, len(hexChars)/2)

	for i := range bytes {
		highNibble := hexCharToNibble(api, hexChars[i*2])
		lowNibble := hexCharToNibble(api, hexChars[i*2+1])

		// Combine nibbles: (high << 4) | low
		byteVal := api.Add(api.Mul(highNibble, 16), lowNibble)

		// Use ValueOf to create a constrained U8 from the frontend.Variable
		bytes[i] = bf.ValueOf(byteVal)
	}

	return bytes, nil
}

// Convert a single lowercase hex character ('0'-'9', 'a'-'f') to its nibble value (0-15)
func hexCharToNibble(api frontend.API, char uints.U8) frontend.Variable {
	// '0'-'9' (ASCII 48-57) -> 0-9
	// 'a'-'f' (ASCII 97-102) -> 10-15

	charVal := char.Val

	// Compute both transformations
	digitValue := api.Sub(charVal, 48)  // For '0'-'9'
	letterValue := api.Sub(charVal, 87) // For 'a'-'f'

	// Check if character code >= 97 ('a')
	// Use a threshold check: if charVal >= 97, it's a letter
	// diff := api.Sub(charVal, 97)

	// If diff >= 0, it's a letter (use letterValue)
	// If diff < 0, it's a digit (use digitValue)
	// We can check if diff >= 0 by seeing if it equals its absolute value

	// Simpler: check if charVal - 97 is non-negative
	// Use comparison: charVal >= 97
	cmpResult := api.Cmp(charVal, 96) // Compare with 96 (one before 'a')
	// cmpResult = 1 if charVal > 96 (i.e., >= 97), meaning it's a letter
	// cmpResult = 0 if charVal == 96 (impossible)
	// cmpResult = -1 if charVal < 96, meaning it's a digit

	isLetter := api.IsZero(api.Sub(cmpResult, 1)) // 1 if cmpResult == 1, else 0

	result := api.Select(isLetter, letterValue, digitValue)

	return result
}

// DecodeBase64Url decodes a base64url encoded string to bytes
func DecodeBase64Url(api frontend.API, base64Chars []uints.U8) ([]uints.U8, error) {
	inputLen := len(base64Chars)

	// Calculate output size based on input length
	numCompleteGroups := inputLen / 4
	remainingChars := inputLen % 4

	outputSize := numCompleteGroups * 3
	if remainingChars == 2 {
		outputSize += 1
	} else if remainingChars == 3 {
		outputSize += 2
	} else if remainingChars == 1 {
		return nil, fmt.Errorf("invalid base64 length: cannot have 1 remaining character")
	}

	// Initialize Bytes API
	bf, err := uints.NewBytes(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create bytes API: %w", err)
	}

	bytes := make([]uints.U8, outputSize)
	outputIdx := 0

	// Process complete groups of 4 characters
	for i := 0; i < numCompleteGroups; i++ {
		c1 := base64Chars[i*4]
		c2 := base64Chars[i*4+1]
		c3 := base64Chars[i*4+2]
		c4 := base64Chars[i*4+3]

		v1 := base64UrlCharToValue(api, c1)
		v2 := base64UrlCharToValue(api, c2)
		v3 := base64UrlCharToValue(api, c3)
		v4 := base64UrlCharToValue(api, c4)

		// Each base64 char represents 6 bits
		// We need to extract specific bits for each output byte

		// byte1 = v1[5:0] << 2 | v2[5:4]
		// byte1 = v1 * 4 + v2 / 16
		byte1_v1 := api.Mul(v1, 4)          // v1 << 2
		byte1_v2 := divideBy16(api, bf, v2) // v2 >> 4 (upper 2 bits)
		byte1 := api.Add(byte1_v1, byte1_v2)

		// byte2 = v2[3:0] << 4 | v3[5:2]
		v2_lower := moduloBy16(api, bf, v2) // v2 & 0xF (lower 4 bits)
		byte2_v2 := api.Mul(v2_lower, 16)   // v2_lower << 4
		byte2_v3 := divideBy4(api, bf, v3)  // v3 >> 2 (upper 4 bits)
		byte2 := api.Add(byte2_v2, byte2_v3)

		// byte3 = v3[1:0] << 6 | v4[5:0]
		v3_lower := moduloBy4(api, bf, v3) // v3 & 0x3 (lower 2 bits)
		byte3_v3 := api.Mul(v3_lower, 64)  // v3_lower << 6
		byte3 := api.Add(byte3_v3, v4)     // v4 is already 6 bits

		bytes[outputIdx] = bf.ValueOf(byte1)
		bytes[outputIdx+1] = bf.ValueOf(byte2)
		bytes[outputIdx+2] = bf.ValueOf(byte3)
		outputIdx += 3
	}

	// Process remaining characters
	if remainingChars == 2 {
		c1 := base64Chars[numCompleteGroups*4]
		c2 := base64Chars[numCompleteGroups*4+1]

		v1 := base64UrlCharToValue(api, c1)
		v2 := base64UrlCharToValue(api, c2)

		byte1_v1 := api.Mul(v1, 4)
		byte1_v2 := divideBy16(api, bf, v2)
		byte1 := api.Add(byte1_v1, byte1_v2)

		bytes[outputIdx] = bf.ValueOf(byte1)
	} else if remainingChars == 3 {
		c1 := base64Chars[numCompleteGroups*4]
		c2 := base64Chars[numCompleteGroups*4+1]
		c3 := base64Chars[numCompleteGroups*4+2]

		v1 := base64UrlCharToValue(api, c1)
		v2 := base64UrlCharToValue(api, c2)
		v3 := base64UrlCharToValue(api, c3)

		byte1_v1 := api.Mul(v1, 4)
		byte1_v2 := divideBy16(api, bf, v2)
		byte1 := api.Add(byte1_v1, byte1_v2)

		v2_lower := moduloBy16(api, bf, v2)
		byte2_v2 := api.Mul(v2_lower, 16)
		byte2_v3 := divideBy4(api, bf, v3)
		byte2 := api.Add(byte2_v2, byte2_v3)

		bytes[outputIdx] = bf.ValueOf(byte1)
		bytes[outputIdx+1] = bf.ValueOf(byte2)
	}

	return bytes, nil
}

// Helper functions to perform proper integer division and modulo
// These work by enumerating all possible 6-bit values (0-63)

func divideBy4(api frontend.API, bf *uints.Bytes, v frontend.Variable) frontend.Variable {
	// v / 4 for v in [0, 63]
	result := frontend.Variable(0)
	for i := 0; i < 64; i++ {
		isValue := api.IsZero(api.Sub(v, i))
		result = api.Select(isValue, i/4, result)
	}
	return result
}

func divideBy16(api frontend.API, bf *uints.Bytes, v frontend.Variable) frontend.Variable {
	// v / 16 for v in [0, 63]
	result := frontend.Variable(0)
	for i := 0; i < 64; i++ {
		isValue := api.IsZero(api.Sub(v, i))
		result = api.Select(isValue, i/16, result)
	}
	return result
}

func moduloBy4(api frontend.API, bf *uints.Bytes, v frontend.Variable) frontend.Variable {
	// v % 4 for v in [0, 63]
	result := frontend.Variable(0)
	for i := 0; i < 64; i++ {
		isValue := api.IsZero(api.Sub(v, i))
		result = api.Select(isValue, i%4, result)
	}
	return result
}

func moduloBy16(api frontend.API, bf *uints.Bytes, v frontend.Variable) frontend.Variable {
	// v % 16 for v in [0, 63]
	result := frontend.Variable(0)
	for i := 0; i < 64; i++ {
		isValue := api.IsZero(api.Sub(v, i))
		result = api.Select(isValue, i%16, result)
	}
	return result
}

func base64UrlCharToValue(api frontend.API, char uints.U8) frontend.Variable {
	charVal := char.Val

	// Initialize result as 0
	result := frontend.Variable(0)

	// Build up result by checking each possible character
	// 'A'-'Z' (65-90) -> 0-25
	for i := 0; i < 26; i++ {
		isChar := api.IsZero(api.Sub(charVal, 65+i))
		result = api.Select(isChar, i, result)
	}

	// 'a'-'z' (97-122) -> 26-51
	for i := 0; i < 26; i++ {
		isChar := api.IsZero(api.Sub(charVal, 97+i))
		result = api.Select(isChar, 26+i, result)
	}

	// '0'-'9' (48-57) -> 52-61
	for i := 0; i < 10; i++ {
		isChar := api.IsZero(api.Sub(charVal, 48+i))
		result = api.Select(isChar, 52+i, result)
	}

	// '-' (45) -> 62
	isDash := api.IsZero(api.Sub(charVal, 45))
	result = api.Select(isDash, 62, result)

	// '_' (95) -> 63
	isUnderscore := api.IsZero(api.Sub(charVal, 95))
	result = api.Select(isUnderscore, 63, result)

	return result
}

func VerifyES256(api frontend.API, message []uints.U8, publicKey ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], signature ecdsa.Signature[emulated.P256Fr]) {
	messageHash, _ := SHA256(api, message)

	mHash, _ := sha256ToP256Fr(api, messageHash)

	// // signature verification assertion is done in-circuit
	publicKey.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &signature)

}

// sha256ToP256Fr converts SHA256 hash output ([]uints.U8) to P256Fr field element
func sha256ToP256Fr(api frontend.API, hash []uints.U8) (*emulated.Element[emulated.P256Fr], error) {
	if len(hash) != 32 {
		panic("SHA256 hash must be 32 bytes")
	}

	field, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}

	// P256Fr uses 4 limbs of 64 bits each (standard for 256-bit fields in gnark)
	// Limbs are stored in little-endian order
	const nbLimbs = 4
	const bytesPerLimb = 8

	limbs := make([]frontend.Variable, nbLimbs)

	// Pack bytes into limbs (little-endian limb order)
	// hash[0..7] -> limb[0] (least significant)
	// hash[8..15] -> limb[1]
	// hash[16..23] -> limb[2]
	// hash[24..31] -> limb[3] (most significant)
	for i := range nbLimbs {
		var limbVal frontend.Variable = 0

		// Process 8 bytes for this limb (little-endian within limb)
		for j := range bytesPerLimb {
			// Read from end of hash going backwards (to match little-endian)
			byteIdx := len(hash) - 1 - (i*bytesPerLimb + j)

			if byteIdx >= 0 && byteIdx < len(hash) {
				// Shift: multiply by 2^(j*8) = 256^j
				shift := frontend.Variable(1)
				for range j {
					shift = api.Mul(shift, 256)
				}
				limbVal = api.Add(limbVal, api.Mul(hash[byteIdx].Val, shift))
			}
		}

		limbs[i] = limbVal
	}

	// Create element with properly structured limbs
	result := &emulated.Element[emulated.P256Fr]{
		Limbs: limbs,
	}

	// Reduce to ensure it's in the correct range
	return field.Reduce(result), nil
}

func ComparePublicKeys(api frontend.API, PubKeyX, PubKeyY emulated.Element[Secp256r1Fp], PubKeyBytes []uints.U8) {

	// public key to bytes
	xBytes := EmulatedElementToBytes32(api, PubKeyX)
	yBytes := EmulatedElementToBytes32(api, PubKeyY)

	// Create the 0x04 prefix for uncompressed point
	prefix := uints.NewU8(4)

	// Concatenate: 0x04 || X || Y (total 65 bytes)
	pubKeyBytes := append(xBytes, yBytes...)
	pubKeyBytes = append([]uints.U8{prefix}, pubKeyBytes...)

	CompareBytes(api, pubKeyBytes, PubKeyBytes)
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

func VerifyJWS(api frontend.API, protected []uints.U8, payload []uints.U8, publicKey ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], signature ecdsa.Signature[emulated.P256Fr]) {
	// Initialize SHA256 hash
	hash, err := sha2.New(api)
	if err != nil {
		return
	}

	// Concatenate header and payload with a '.' separator (ASCII 46 = 0x2E)
	// format: base64url(header).base64url(payload)
	dotSeparator := uints.NewU8(46)

	// Write header to hasher
	hash.Write(protected)

	// Write dot separator
	hash.Write([]uints.U8{dotSeparator})

	// Write payload to hasher
	hash.Write(payload)

	// Compute SHA256 hash of header.payload
	messageHash := hash.Sum()

	// Convert to P256Fr
	mHash, err := sha256ToP256Fr(api, messageHash)
	if err != nil {
		return
	}

	// Verify the signature
	publicKey.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &signature)

}
