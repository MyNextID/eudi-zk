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
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	csv "github.com/mynextid/gnark-eudi/circuits/signature-verification"
	"github.com/mynextid/gnark-eudi/common"
)

const (
	ccsPath = "compiled/circuit.ccs"
	pkPath  = "compiled/proving.key"
	vkPath  = "compiled/verifying.key"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func TestJWTCircuit_Define(t *testing.T) {
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
	signatureBytes := append(common.PadTo32Bytes(r.Bytes()), common.PadTo32Bytes(s.Bytes())...)
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

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	fmt.Println("\n--- Loading the circuit ---")
	startCircuit := time.Now()
	// Check if files exist
	if _, err := os.Stat(pkPath); os.IsNotExist(err) {
		// First time: compile and save
		circuitTemplate := &csv.JWTCircuit{
			JWTHeaderB64:     make([]uints.U8, len(headerB64)),
			JWTPayloadPublic: make([]uints.U8, len(payloadB64)),
			SignerCertDER:    make([]uints.U8, len(tbsCert)),
		}
		if err := common.SetupAndSave(circuitTemplate, ccsPath, pkPath, vkPath); err != nil {
			panic(err)
		}
		// Load what we just saved
		ccs, pk, vk, err = common.LoadSetup(ccsPath, pkPath, vkPath)
		if err != nil {
			panic(err)
		}
	} else {
		// Subsequent runs: just load
		ccs, pk, vk, err = common.LoadSetup(ccsPath, pkPath, vkPath)
		if err != nil {
			panic(err)
		}
	}

	// Create witness assignment with actual values
	assignment := &csv.JWTCircuit{
		// Private inputs
		JWTHeaderB64:  common.StringToU8Array(headerB64),
		JWTSigR:       emulated.ValueOf[Secp256r1Fr](r),
		JWTSigS:       emulated.ValueOf[Secp256r1Fr](s),
		SignerPubKeyX: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerCertDER: common.BytesToU8Array(tbsCert),
		CertSigR:      emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:      emulated.ValueOf[Secp256r1Fr](certSig.S),

		// Public input
		JWTPayloadPublic: common.StringToU8Array(payloadB64),
		QTSPPubKeyX:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		QTSPPubKeyY:      emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// Create witness
	fmt.Println("\n--- Creating Witness ---")
	startWitness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessTime := time.Since(startWitness)
	fmt.Printf("✓ Witness created successfully! (took %v)\n", witnessTime)

	// Generate proof
	fmt.Println("\n--- Generating Proof ---")
	startProof := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	proofTime := time.Since(startProof)
	fmt.Printf("✓ Proof generated successfully! (took %v)\n", proofTime)

	// Extract public witness for verification
	fmt.Println("\n--- Extracting Public Witness ---")
	startPublic := time.Now()
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	publicTime := time.Since(startPublic)
	fmt.Printf("✓ Public witness extracted! (took %v)\n", publicTime)

	// Verify proof
	fmt.Println("\n--- Verifying Proof ---")
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic("❌ Verification failed: " + err.Error())
	}
	verifyTime := time.Since(startVerify)
	fmt.Printf("✅ Proof verified successfully! (took %v)\n", verifyTime)

	// Summary
	fmt.Println("\n=== Performance Summary ===")
	fmt.Printf("Circuit creation:  %v\n", circuitTime)
	fmt.Printf("Witness creation:  %v\n", witnessTime)
	fmt.Printf("Proof generation:  %v\n", proofTime)
	fmt.Printf("Public extraction: %v\n", publicTime)
	fmt.Printf("Verification:      %v\n", verifyTime)
	fmt.Printf("Total time:        %v\n", witnessTime+proofTime+publicTime+verifyTime)

}
