package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"
)

// Define a simple test signer
type Simple struct {
	secretKey            *ecdsa.PrivateKey
	PublicKeyCertificate *x509.Certificate
}

// CAdES options; for now only detached true/false
type CAdESOpts struct {
	Detached bool // default: false
}

func (opts CAdESOpts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (s Simple) Sign(rand io.Reader, data []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	// Default values
	detached := false

	// Type assert to your custom options
	if cadesOpts, ok := opts.(CAdESOpts); ok {
		detached = cadesOpts.Detached
	}

	if detached {
		return CreateDetachedCAdESSignature(data, s.secretKey, s.PublicKeyCertificate)
	}
	return SignWithCAdES(data, s.secretKey, s.PublicKeyCertificate)
}

func (s Simple) Public() crypto.PublicKey {
	return s.secretKey.PublicKey
}

func NewTestSigner() (crypto.Signer, error) {

	// generate secp256r1 (P-256) key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "CAdES Test Signer",
			Organization: []string{"Test Organization"},
			Country:      []string{"SI"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return Simple{
		secretKey:            privateKey,
		PublicKeyCertificate: cert,
	}, nil
}
