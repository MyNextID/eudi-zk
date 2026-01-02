package verifyjwscert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mynextid/eudi-zk/circuits"
	verifyjwscert "github.com/mynextid/eudi-zk/circuits/verify-jws-cert"
	"github.com/mynextid/eudi-zk/zkcore"
)

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

func TestCircuit(t *testing.T) {

	saveExamplePayload := true

	zkc, err := circuits.Compile(verifyjwscert.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	data := MockData()

	pvtIn := verifyjwscert.PrivateInput{
		Protected: data.Protected,
		Signature: data.Signature,
		Hash:      data.Hash,
		X5C:       data.X5C,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := verifyjwscert.PublicInput{
		Payload:       data.Payload,
		QTSPPublicKey: data.QTSPPublicKey,
	}
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

// ========================================================================
// MOCK DATA GENERATOR
// ========================================================================

// JWS represents a complete JWS with certificate chain
type JWS struct {
	Protected     string
	Payload       string
	Signature     string
	X5C           string
	QTSPPublicKey string
	Hash          string
}

// MockData generates test data for the circuit
func MockData() *JWS {
	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}
	// Create a JWS header
	header := map[string]any{
		"alg": "ES256",
		"typ": "JOSE+JSON",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal header: %v", err))
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	// Create JWS payload
	payload := map[string]any{
		"sub":  "1234567890",
		"name": "Alice Wonderland",
		"iat":  1516239022,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal payload: %v", err))
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	// Create signing input: header.payload
	signingInput := headerB64 + "." + payloadB64
	// Hash the signing input with SHA-256
	hash := sha256.Sum256([]byte(signingInput))
	// Sign the hash with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, hash[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to sign: %v", err))
	}
	// Create the complete JWS
	signatureBytes := append(zkcore.PadTo32Bytes(r.Bytes()), zkcore.PadTo32Bytes(s.Bytes())...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)
	// jwtToken := signingInput + "." + signatureB64

	// == Create the x509 cert ==
	// Generate certificate issuer (QTSP) key pair
	qtspKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("failed to generate issuer key: %w", err))
	}
	// Create X.509 certificate signed by issuer
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Signer",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &signerKey.PublicKey, qtspKey)
	if err != nil {
		panic(fmt.Errorf("failed to create certificate: %w", err))
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(fmt.Errorf("failed to parse certificate: %w", err))
	}
	// Extract TBS (To-Be-Signed) certificate
	tbsCert := cert.RawTBSCertificate
	// Extract the signature from the certificate
	var certSig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(cert.Signature, &certSig)
	if err != nil {
		// we need to re-sign to get the proper signature components
		tbsHash := sha256.Sum256(tbsCert)
		certSig.R, certSig.S, err = ecdsa.Sign(rand.Reader, qtspKey, tbsHash[:])
		if err != nil {
			panic(fmt.Errorf("failed to sign certificate: %w", err))
		}
	}

	// Encode certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode QTSP public key as PEM
	qtspPubKeyBytes, err := x509.MarshalPKIXPublicKey(&qtspKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("failed to marshal QTSP public key: %w", err))
	}
	qtspPubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: qtspPubKeyBytes,
	})

	return &JWS{
		Protected:     headerB64,
		Payload:       payloadB64,
		Signature:     signatureB64,
		X5C:           string(certPEM),
		QTSPPublicKey: string(qtspPubKeyPEM),
		Hash:          base64.RawURLEncoding.EncodeToString(hash[:]),
	}
}
