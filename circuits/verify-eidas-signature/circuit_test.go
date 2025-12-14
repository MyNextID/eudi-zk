package csv_test

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
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	csv "github.com/mynextid/eudi-zk/circuits/verify-eidas-signature"
	"github.com/mynextid/eudi-zk/common"
)

const (
	ccsPath = "compiled/circuit.ccs"
	pkPath  = "compiled/proving.key"
	vkPath  = "compiled/verifying.key"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

func TestJWSCircuit_Define(t *testing.T) {
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
	signatureBytes := append(common.PadTo32Bytes(r.Bytes()), common.PadTo32Bytes(s.Bytes())...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)
	jwtToken := signingInput + "." + signatureB64

	fmt.Println("Generated JWS:", jwtToken)
	fmt.Println("\n--- Circuit Inputs ---")
	fmt.Printf("Header JSON length: %d bytes\n", len(headerJSON))
	fmt.Printf("Payload B64 length: %d bytes\n", len(payloadB64))

	// == Crate the x509 cert ==
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

	// == Circuit ==
	circuitTemplate := &csv.CircuitJWS{
		JWSHeaderB64:     make([]uints.U8, len(headerB64)),
		JWSPayloadPublic: make([]uints.U8, len(payloadB64)),
		SignerCertDER:    make([]uints.U8, len(tbsCert)),
	}

	// create witness assignment with actual values
	assignment := &csv.CircuitJWS{
		// Private inputs
		JWSHeaderB64:  common.StringToU8Array(headerB64),
		JWSSigR:       emulated.ValueOf[Secp256r1Fr](r),
		JWSSigS:       emulated.ValueOf[Secp256r1Fr](s),
		SignerPubKeyX: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerCertDER: common.BytesToU8Array(tbsCert),
		CertSigR:      emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:      emulated.ValueOf[Secp256r1Fr](certSig.S),

		// Public input
		JWSPayloadPublic: common.StringToU8Array(payloadB64),
		QTSPPubKeyX:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		QTSPPubKeyY:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
	}

	// == Init the circuit ==
	forceCompile := true
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to inititalize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)

}

func TestX509(t *testing.T) {
	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// == Crate the x509 cert ==
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

}
