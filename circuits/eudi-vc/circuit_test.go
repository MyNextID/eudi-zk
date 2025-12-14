package cdl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	cdl "github.com/mynextid/eudi-zk/circuits/eudi-vc"
	"github.com/mynextid/eudi-zk/common"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

func TestEUDI(t *testing.T) {
	// Set a deadline for this specific test
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// == Circuit data ==
	ccsPath := "compiled/circuit-eudi-v1.ccs"
	pkPath := "compiled/proving-eudi-v1.key"
	vkPath := "compiled/verifying-eudi-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair of the credential subject/holder
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	subPubKeyBytes := elliptic.Marshal(elliptic.P256(), subjectKey.PublicKey.X, subjectKey.PublicKey.Y)

	// Hash the encoded public key
	pkDigest := sha256.Sum256(subPubKeyBytes)

	subPkDigestHex := hex.EncodeToString(pkDigest[:])

	// Generate ES256 (P-256) key pair of the credential issuer
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Issue the credential

	// Create a JWS header
	// TODO: replace kid with cnf
	header := map[string]any{
		"alg": "ES256",
		"kid": subPkDigestHex,
		"typ": "JOSE+JSON",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal header: %v", err))
	}
	// Find where "kid":" appears, then move past it to the value
	kidKeyPos := strings.Index(string(headerJSON), `"kid":"`)
	if kidKeyPos == -1 {
		panic("kid field not found in JSON")
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Move past `"kid":"` to get to the start of the value
	kidValueStart := kidKeyPos + len(`"kid":"`)
	kidValueEnd := kidValueStart + len(subPkDigestHex)
	fmt.Printf("kid value starts at byte position: %d\n", kidValueStart)
	fmt.Println(subPkDigestHex)
	fmt.Println(string(headerJSON[kidValueStart:kidValueEnd]))

	isLast := (len(headerJSON) - 2) == kidValueEnd
	_ = isLast

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
	jwsR, jwsS, err := ecdsa.Sign(rand.Reader, issuerKey, hash[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to sign: %v", err))
	}

	// Create the complete JWS
	signatureBytes := append(common.PadTo32Bytes(jwsR.Bytes()), common.PadTo32Bytes(jwsS.Bytes())...)
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

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &subjectKey.PublicKey, qtspKey)
	if err != nil {
		panic(fmt.Errorf("failed to create certificate: %w", err))
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(fmt.Errorf("failed to parse certificate: %w", err))
	}

	// Extract TBS (To-Be-Signed) certificate
	tbsCert := cert.RawTBSCertificate

	// Find public key position
	pubKeyPosition, err := cdl.FindSubjectPublicKeyPositionInTBS(tbsCert)
	if err != nil {
		t.Errorf("finding subject public key position failed: %v", err)
	}

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

	// == create and sign the challenge ==
	challenge, err := common.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to create a challenge %v", err)
	}

	c_digest := sha256.Sum256(challenge)

	// Sign the digest of the challenge
	r, s, err := ecdsa.Sign(rand.Reader, subjectKey, c_digest[:])
	if err != nil {
		t.Fatalf("failed to sign the challenge %v", err)
	}

	// == create the circuit and execute it ==
	circuitTemplate := &cdl.CircuitEUDI{
		CertBytes:    make([]uints.U8, len(tbsCert)),
		Challenge:    make([]uints.U8, len(challenge)),
		JWSProtected: make([]uints.U8, len(headerB64)),
		JWSPayload:   make([]uints.U8, len(payloadB64)),
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitEUDI{
		CertBytes:           common.BytesToU8Array(tbsCert),
		CertLength:          frontend.Variable(len(tbsCert)),
		CertSigR:            emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:            emulated.ValueOf[Secp256r1Fr](certSig.S),
		SubjectPubKeyPos:    frontend.Variable(pubKeyPosition),
		SubjectPubKeyX:      emulated.ValueOf[Secp256r1Fp](subjectKey.PublicKey.X),
		SubjectPubKeyY:      emulated.ValueOf[Secp256r1Fp](subjectKey.PublicKey.Y),
		ChallengeSignatureR: emulated.ValueOf[Secp256r1Fr](r),
		ChallengeSignatureS: emulated.ValueOf[Secp256r1Fr](s),
		JWSR:                emulated.ValueOf[Secp256r1Fr](jwsR),
		JWSS:                emulated.ValueOf[Secp256r1Fr](jwsS),
		JWSProtected:        common.StringToU8Array(headerB64),
		Challenge:           common.BytesToU8Array(challenge),
		CAPubKeyX:           emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		CAPubKeyY:           emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
		IssuerPubKeyX:       emulated.ValueOf[Secp256r1Fp](issuerKey.PublicKey.X),
		IssuerPubKeyY:       emulated.ValueOf[Secp256r1Fp](issuerKey.PublicKey.Y),
		JWSPayload:          common.StringToU8Array(payloadB64),
	}

	// == Init the circuit ==
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

func TestPoPCA(t *testing.T) {
	// Set a deadline for this specific test
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// == Circuit data ==
	ccsPath := "compiled/circuit-pop-ca-v1.ccs"
	pkPath := "compiled/proving-pop-ca-v1.key"
	vkPath := "compiled/verifying-pop-ca-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

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

	// Find public key position
	pubKeyPosition, err := cdl.FindSubjectPublicKeyPositionInTBS(tbsCert)
	if err != nil {
		t.Errorf("finding subject public key position failed: %v", err)
	}

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

	// == create and sign the challenge ==
	challenge, err := common.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to create a challenge %v", err)
	}

	c_digest := sha256.Sum256(challenge)

	// Sign the digest of the challenge
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, c_digest[:])
	if err != nil {
		t.Fatalf("failed to sign the challenge %v", err)
	}

	// == create the circuit and execute it ==
	circuitTemplate := &cdl.CircuitPoPCA{
		CertBytes: make([]uints.U8, len(tbsCert)),
		Challenge: make([]uints.U8, len(challenge)),
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitPoPCA{
		CertBytes:           common.BytesToU8Array(tbsCert),
		CertLength:          frontend.Variable(len(tbsCert)),
		CertSigR:            emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:            emulated.ValueOf[Secp256r1Fr](certSig.S),
		SubjectPubKeyPos:    frontend.Variable(pubKeyPosition),
		SignerPubKeyX:       emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY:       emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		ChallengeSignatureR: emulated.ValueOf[Secp256r1Fr](r),
		ChallengeSignatureS: emulated.ValueOf[Secp256r1Fr](s),
		Challenge:           common.BytesToU8Array(challenge),
		CAPubKeyX:           emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		CAPubKeyY:           emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
	}

	// == Init the circuit ==
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

func TestPoP(t *testing.T) {
	// Set a deadline for this specific test
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// == Circuit data ==
	ccsPath := "compiled/circuit-pop-v1.ccs"
	pkPath := "compiled/proving-pop-v1.key"
	vkPath := "compiled/verifying-pop-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

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

	// Find public key position
	pubKeyPosition, err := cdl.FindSubjectPublicKeyPosition(certDER)
	if err != nil {
		t.Errorf("finding subject public key position failed: %v", err)
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

	// == create and sign the challenge ==
	challenge, err := common.GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to create a challenge %v", err)
	}

	c_digest := sha256.Sum256(challenge)

	// Sign the digest of the challenge
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, c_digest[:])
	if err != nil {
		t.Fatalf("failed to sign the challenge %v", err)
	}

	// == create the circuit and execute it ==
	circuitTemplate := &cdl.CircuitPoP{
		CertBytes: make([]uints.U8, len(certDER)),
		Challenge: make([]uints.U8, len(challenge)),
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitPoP{
		CertBytes:           common.BytesToU8Array(certDER),
		CertLength:          frontend.Variable(len(certDER)),
		SubjectPubKeyPos:    frontend.Variable(pubKeyPosition),
		SignerPubKeyX:       emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY:       emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		ChallengeSignatureR: emulated.ValueOf[Secp256r1Fr](r),
		ChallengeSignatureS: emulated.ValueOf[Secp256r1Fr](s),
		Challenge:           common.BytesToU8Array(challenge),
	}

	// == Init the circuit ==
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

func TestSubjectPublicKey(t *testing.T) {
	// == Circuit data ==
	ccsPath := "compiled/circuit-spk-v1.ccs"
	pkPath := "compiled/proving-spk-v1.key"
	vkPath := "compiled/verifying-spk-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

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

	// Find public key position
	pubKeyPosition, err := cdl.FindSubjectPublicKeyPosition(certDER)
	if err != nil {
		t.Errorf("finding subject public key position failed: %v", err)
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

	circuitTemplate := &cdl.CircuitSPK{
		CertBytes:         make([]uints.U8, len(certDER)),
		SignerPubKeyBytes: make([]uints.U8, len(pubKeyBytes)),
	}

	// Create witness assignment with actual values
	assignment := &cdl.CircuitSPK{
		CertBytes:         common.BytesToU8Array(certDER),
		CertLength:        frontend.Variable(len(certDER)),
		SignerPubKeyBytes: common.BytesToU8Array(pubKeyBytes),
		SubjectPubKeyPos:  frontend.Variable(pubKeyPosition),
	}

	// == Init the circuit ==
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
