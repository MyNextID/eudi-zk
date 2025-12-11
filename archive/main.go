package main

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
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func main() {
	// == create dummy data ==
	// 1. Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// 2. Create JWT header
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal header: %v", err))
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 3. Create JWT payload
	payload := map[string]interface{}{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal payload: %v", err))
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// 4. Create signing input: header.payload
	signingInput := headerB64 + "." + payloadB64

	// 5. Hash the signing input with SHA-256
	hash := sha256.Sum256([]byte(signingInput))

	// 6. Sign the hash with ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, hash[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to sign: %v", err))
	}

	// 7. Create the complete JWT
	signatureBytes := append(padTo32Bytes(r.Bytes()), padTo32Bytes(s.Bytes())...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)
	jwtToken := signingInput + "." + signatureB64

	fmt.Println("Generated JWT:", jwtToken)
	fmt.Println("\n--- Circuit Inputs ---")
	fmt.Printf("Header JSON length: %d bytes\n", len(headerJSON))
	fmt.Printf("Payload B64 length: %d bytes\n", len(payloadB64))

	// == Crate the x509 cert ==
	// 1. Generate issuer (QTSP) key pair
	qtspKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("failed to generate issuer key: %w", err))
	}
	// 3. Create X.509 certificate signed by issuer
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

	// == circuit ==
	// Define the circuit template for compilation (with empty slices of correct size)

	ccsPath := "circuit.ccs"
	pkPath := "proving.key"
	vkPath := "verifying.key"

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// Check if files exist
	if _, err := os.Stat(pkPath); os.IsNotExist(err) {
		// First time: compile and save
		circuitTemplate := &JWTCircuit{
			JWTHeaderB64:     make([]uints.U8, len(headerB64)),
			JWTPayloadPublic: make([]uints.U8, len(payloadB64)),
			SignerCertDER:    make([]uints.U8, len(tbsCert)),
		}
		if err := SetupAndSave(circuitTemplate, ccsPath, pkPath, vkPath); err != nil {
			panic(err)
		}
		// Load what we just saved
		ccs, pk, vk, err = LoadSetup(ccsPath, pkPath, vkPath)
		if err != nil {
			panic(err)
		}
	} else {
		// Subsequent runs: just load
		ccs, pk, vk, err = LoadSetup(ccsPath, pkPath, vkPath)
		if err != nil {
			panic(err)
		}
	}

	// Create witness assignment with actual values
	assignment := &JWTCircuit{
		// Private inputs
		JWTHeaderB64:  stringToU8Array(headerB64),
		JWTSigR:       emulated.ValueOf[Secp256r1Fr](r),
		JWTSigS:       emulated.ValueOf[Secp256r1Fr](s),
		SignerPubKeyX: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerCertDER: bytesToU8Array(tbsCert),
		CertSigR:      emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:      emulated.ValueOf[Secp256r1Fr](certSig.S),

		// Public input
		JWTPayloadPublic: stringToU8Array(payloadB64),
		QTSPPubKeyX:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		QTSPPubKeyY:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
	}

	// Create witness
	fmt.Println("\n--- Creating Witness ---")
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Witness created successfully!")

	// Generate proof
	fmt.Println("\n--- Generating Proof ---")
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ Proof generated successfully!")

	// Extract public witness for verification
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Verify proof
	fmt.Println("\n--- Verifying Proof ---")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic("❌ Verification failed: " + err.Error())
	}
	fmt.Println("✅ Proof verified successfully!")
}

// Helper function to convert string to []uints.U8
func stringToU8Array(s string) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range []byte(s) {
		result[i] = uints.NewU8(b)
	}
	return result
}

// Helper function to convert string to []uints.U8
func bytesToU8Array(s []byte) []uints.U8 {
	result := make([]uints.U8, len(s))
	for i, b := range s {
		result[i] = uints.NewU8(b)
	}
	return result
}

// Helper function to pad bytes to 32 bytes (needed for P-256 signature components)
func padTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}
