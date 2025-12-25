package models

// Signer provides cryptographic signing for presentations
type Signer interface {
	// Sign signs the given data and returns the signature
	Sign(data []byte) ([]byte, error)
	// GetKeyID returns the identifier for this signing key
	GetKeyID() string
}
