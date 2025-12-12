package common

import (
	"fmt"

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
