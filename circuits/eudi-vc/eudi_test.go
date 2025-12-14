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
	header := map[string]any{
		"alg": "ES256",
		"cnf": map[string]string{
			"kid": subPkDigestHex,
		},
		"typ": "JOSE+JSON",
	}

	// Create JWS header
	cnf := map[string]any{
		"cnf": map[string]string{
			"kid": subPkDigestHex,
		},
	}

	cnfJSON, err := json.Marshal(cnf)
	if err != nil {
		t.Fatalf("Failed to marshal header: %v", err)
	}

	cnfStr := strings.TrimPrefix(string(cnfJSON), "{")
	cnfStr = strings.TrimSuffix(cnfStr, "}")

	protectedJSON, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal header: %v", err))
	}
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)

	// Find where "cnf":" appears
	cnfStart := strings.Index(string(protectedJSON), cnfStr)
	if cnfStart == -1 {
		t.Fatal("cnf field not found in JSON")
	}
	// Length of the cnf variable
	cnfLen := len(cnfStr)
	cnfEnd := cnfStart + cnfLen

	cnfStartNew, cnfEndNew := common.B64Align(cnfStart, cnfEnd)

	cnfAligned := protectedJSON[cnfStartNew:cnfEndNew]
	cnfAlignedB64 := base64.RawURLEncoding.EncodeToString([]byte(cnfAligned))

	isSubset := strings.Contains(protectedB64, cnfAlignedB64)
	if !isSubset {
		t.Log(protectedB64)
		t.Log(cnfAlignedB64)
		t.Fatal("cnf is not a subset")
	}

	cnfB64Index := strings.Index(protectedB64, cnfAlignedB64)
	if cnfStart == -1 {
		t.Fatal("failed to get cnfB64 index")
	}
	// get the public key position
	pubKeyIndex := strings.Index(string(cnfAligned), subPkDigestHex)
	if cnfStart == -1 {
		t.Fatal("public key not found in JSON")
	}

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
	signingInput := protectedB64 + "." + payloadB64

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
	fmt.Printf("Header JSON length: %d bytes\n", len(protectedJSON))
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
		CnfB64:       make([]uints.U8, len(cnfAlignedB64)),
		JWSProtected: make([]uints.U8, len(protectedB64)),
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
		JWSProtected:        common.StringToU8Array(protectedB64),
		CnfB64:              common.StringToU8Array(cnfAlignedB64),
		CnfB64Position:      cnfB64Index,
		CnfKeyHexPosition:   pubKeyIndex,
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
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuitSimple(assignment, ccs, pk, vk)
}
