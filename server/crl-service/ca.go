// Package crlservice implements demo mini CRL and domain-bound CRL
package crlservice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// CAManager handles CA certificate and private key operations
type CAManager struct {
	cert       *x509.Certificate
	privateKey *ecdsa.PrivateKey
}

// NewCAManager creates a new CA manager with a self-signed root certificate
func NewCAManager() (*CAManager, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Demo CA"},
			CommonName:   "Demo Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return &CAManager{
		cert:       cert,
		privateKey: privateKey,
	}, nil
}

// SignCRL signs a CRL using the CA's private key
func (ca *CAManager) SignCRL(template *x509.RevocationList) ([]byte, error) {
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation list: %w", err)
	}
	return crlDER, nil
}
