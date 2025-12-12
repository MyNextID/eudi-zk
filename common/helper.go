package common

import (
	"crypto/rand"

	"github.com/consensys/gnark/std/math/uints"
)

// Helper function to convert string to []uints.U8
func StringToU8Array(s string) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range []byte(s) {
		result[i] = uints.NewU8(b)
	}
	return result
}

// Helper function to convert string to []uints.U8
func BytesToU8Array(s []byte) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range s {
		result[i] = uints.NewU8(b)
	}
	return result
}

// Helper function to pad bytes to 32 bytes (needed for P-256 signature components)
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
