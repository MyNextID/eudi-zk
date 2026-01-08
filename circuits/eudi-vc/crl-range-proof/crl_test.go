package minicrl_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/mynextid/eudi-zk/circuits"
	minicrl "github.com/mynextid/eudi-zk/circuits/eudi-vc/crl-range-proof"
)

func TestCompareBytesAPI(t *testing.T) {

	saveExamplePayload := true

	// Generate inputs

	zkc, err := circuits.Compile(minicrl.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	data := MockData(t)

	pvtIn := minicrl.PrivateInput{
		CRLBytes:  base64.RawURLEncoding.EncodeToString(data.CRL),
		CertBytes: base64.RawURLEncoding.EncodeToString(data.Cert),
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := minicrl.PublicInput{}
	pubInBuf, _ := json.Marshal(pubIn)

	// create a proof
	proof, err := zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// verify the proof
	err = zkc.VerifyWithJSON(pubInBuf, proof)
	if err != nil {
		t.Fatalf("failed to verify a proof: %v", err)
	}

	// save the sample payload
	if saveExamplePayload {
		proveRequest := circuits.Request{
			Private: pvtIn,
			Public:  pubIn,
		}

		filename := fmt.Sprintf("%s.json", zkc.Info.Name)
		path := filepath.Join("examples", filename)
		err = proveRequest.Save(path)
		if err != nil {
			t.Fatal(err)
		}
	}

}

type Inputs struct {
	CRL  []byte
	Cert []byte
}

func MockData(t *testing.T) Inputs {
	// == Generate test certificate ==
	// Generate certificate key pair
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate certificate key: %v", err)
	}

	// Generate CA key pair for signing
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(pubKeyBytes)

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID[:],
	}

	// Create end-entity certificate template
	serialNumber := big.NewInt(1112)
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, &certKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	fmt.Printf("Certificate Serial Number: %s\n", cert.SerialNumber.String())

	// Create CRL
	// Our cert is not revoked
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1111),
			RevocationTime: time.Now(),
		},
		{
			SerialNumber:   big.NewInt(2222),
			RevocationTime: time.Now(),
		},
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(30 * 24 * time.Hour),
		RevokedCertificates: revokedCerts,
	}

	// sign the CRL
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caTemplate, caKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	fmt.Printf("CRL created with %d revoked certificates\n", len(revokedCerts))
	fmt.Printf("Certificate DER length: %d bytes\n", len(certDER))
	fmt.Printf("CRL DER length: %d bytes\n", len(crlDER))

	return Inputs{
		CRL:  crlDER,
		Cert: certDER,
	}
}

func MockDataRevoked(t *testing.T) Inputs {
	// == Generate test certificate ==
	// Generate certificate key pair
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate certificate key: %v", err)
	}

	// Generate CA key pair for signing
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(pubKeyBytes)

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test Certificate Authority",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID[:],
	}

	// Create end-entity certificate template
	serialNumber := big.NewInt(2112)
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, &certKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	fmt.Printf("Certificate Serial Number: %s\n", cert.SerialNumber.String())

	// Create CRL
	// Our cert is not revoked
	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1111),
			RevocationTime: time.Now(),
		},
		{
			SerialNumber:   big.NewInt(2222),
			RevocationTime: time.Now(),
		},
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(30 * 24 * time.Hour),
		RevokedCertificates: revokedCerts,
	}

	// sign the CRL
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caTemplate, caKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}

	fmt.Printf("CRL created with %d revoked certificates\n", len(revokedCerts))
	fmt.Printf("Certificate DER length: %d bytes\n", len(certDER))
	fmt.Printf("CRL DER length: %d bytes\n", len(crlDER))

	return Inputs{
		CRL:  crlDER,
		Cert: certDER,
	}
}
