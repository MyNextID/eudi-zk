package cdl_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	cdl "github.com/mynextid/eudi-zk/circuits/eudi-vc"
	"github.com/mynextid/eudi-zk/common"
)

func TestCRLNotRevoked(t *testing.T) {

	// == Circuit data ==
	ccsPath := "compiled/circuit-crl-v1.ccs"
	pkPath := "compiled/proving-crl-v1.key"
	vkPath := "compiled/verifying-crl-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

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
	keyId := sha1.Sum(pubKeyBytes)

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
		SubjectKeyId:          keyId[:],
	}

	// Create end-entity certificate template
	serialNumber := big.NewInt(12345)
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
		{
			SerialNumber:   big.NewInt(3333),
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

	// Verify our certificate is NOT in the CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	isRevoked := false
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			isRevoked = true
			break
		}
	}

	if isRevoked {
		t.Fatal("Test certificate should NOT be revoked!")
	}

	fmt.Println("[OK] Verified: Certificate is NOT in the CRL")

	//  New circuit template
	maxSerialLen := 20 // maximum serial number length in bytes

	circuitTemplate := &cdl.CircuitCRL{
		CertBytes:    make([]uints.U8, len(certDER)),
		CRLBytes:     make([]uints.U8, len(crlDER)),
		MaxSerialLen: maxSerialLen,
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitCRL{
		CertBytes:    common.BytesToU8Array(certDER),
		CRLBytes:     common.BytesToU8Array(crlDER),
		MaxSerialLen: maxSerialLen,
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("Failed to initialize circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	fmt.Println("\n--- Running circuit verification ---")
	common.TestCircuitSimple(assignment, ccs, pk, vk)

	fmt.Println("\n[OK] Circuit proof generated and verified successfully!")
	fmt.Println("[OK] Certificate is proven to NOT be revoked")
}

func TestCRLRevoked(t *testing.T) {

	// == Circuit data ==
	ccsPath := "compiled/circuit-crl-v1.ccs"
	pkPath := "compiled/proving-crl-v1.key"
	vkPath := "compiled/verifying-crl-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := false

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
	keyId := sha1.Sum(pubKeyBytes)

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
		SubjectKeyId:          keyId[:],
	}

	// Create end-entity certificate template
	serialNumber := big.NewInt(12345)
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

	// Create the certificate signed by CA
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
			SerialNumber:   big.NewInt(12345),
			RevocationTime: time.Now(),
		},
		{
			SerialNumber:   big.NewInt(3333),
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

	// Verify our certificate is NOT in the CRL
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}

	isRevoked := false
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			isRevoked = true
			break
		}
	}

	if !isRevoked {
		t.Fatal("Test certificate should be revoked!")
	}

	fmt.Println("[OK] Verified: Certificate is in the CRL")

	//  New circuit template
	maxSerialLen := 20 // maximum serial number length in bytes

	circuitTemplate := &cdl.CircuitCRL{
		CertBytes:    make([]uints.U8, len(certDER)),
		CRLBytes:     make([]uints.U8, len(crlDER)),
		MaxSerialLen: maxSerialLen,
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitCRL{
		CertBytes:    common.BytesToU8Array(certDER),
		CRLBytes:     common.BytesToU8Array(crlDER),
		MaxSerialLen: maxSerialLen,
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("Failed to initialize circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	fmt.Println("\n--- Running circuit verification ---")
	common.TestCircuitSimple(assignment, ccs, pk, vk)

	fmt.Println("\n[OK] Circuit proof generated and verified successfully!")
	fmt.Println("[OK] Certificate is proven to be revoked")
}
