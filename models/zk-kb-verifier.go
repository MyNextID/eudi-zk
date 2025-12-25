package models

// Verifier verifies signatures on presentations
type Verifier interface {
	// Verify verifies a signature against the given data and key ID
	Verify(data []byte, signature []byte, keyID string) error
}
