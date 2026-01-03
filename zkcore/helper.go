package zkcore

import (
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark/std/math/uints"
)

// StringToU8Array is helper function to convert string to []uints.U8
func StringToU8Array(s string) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range []byte(s) {
		result[i] = uints.NewU8(b)
	}
	return result
}

// BytesToU8Array is a helper function to convert string to []uints.U8
func BytesToU8Array(s []byte) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range s {
		result[i] = uints.NewU8(b)
	}
	return result
}

// BytesToU8ArrayWithPadding converts bytes to []uints.U8 with padding
// Returns error if input exceeds size limit
func BytesToU8ArrayWithPadding(s []byte, size int) ([]uints.U8, error) {
	if len(s) > size {
		return nil, fmt.Errorf("input length %d exceeds maximum size %d", len(s), size)
	}

	result := make([]uints.U8, size)
	for i := range size {
		if i < len(s) {
			result[i] = uints.NewU8(s[i])
		} else {
			result[i] = uints.NewU8(0) // Initialize padding bytes
		}
	}
	return result, nil
}

// StringToU8ArrayWithPadding converts string to []uints.U8 with padding
// Returns error if input exceeds size limit
func StringToU8ArrayWithPadding(s string, size int) ([]uints.U8, error) {
	return BytesToU8ArrayWithPadding([]byte(s), size)
}

// PadTo32Bytes is a helper function to pad bytes to 32 bytes (needed for P-256 signature components)
func PadTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// GenerateRandomBytes returns cryptographically secure random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}
