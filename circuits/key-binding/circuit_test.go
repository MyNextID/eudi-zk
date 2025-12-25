package ckb_test

import (
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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
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

func TestCompareHex(t *testing.T) {
	// == create dummy data ==
	// 1. Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	// Hash the encoded public key
	pkDigest := sha256.Sum256(pubKeyBytes)

	pkDigestHex := hex.EncodeToString(pkDigest[:])

	// 2. Create JWS header
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWS",
		"kid": pkDigestHex,
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

	// Move past `"kid":"` to get to the start of the value
	kidValueStart := kidKeyPos + len(`"kid":"`)
	fmt.Printf("kid value starts at byte position: %d\n", kidValueStart)

	for i, v := range []byte(pkDigestHex) { // Convert hex string to bytes
		if v != headerJSON[kidValueStart+i] {
			panic(fmt.Errorf("mismatch at: %d", i))
		}
	}
}

func TestCompareB64(t *testing.T) {
	// == create dummy data ==
	// 1. Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	// Hash the encoded public key
	pkDigest := sha256.Sum256(pubKeyBytes)

	pkDigestHex := hex.EncodeToString(pkDigest[:])

	// 2. Create JWS header
	header := map[string]string{
		"alg": "ES256",
		"kid": pkDigestHex,
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
	kidValueEnd := kidValueStart + len(pkDigestHex)
	fmt.Printf("kid value starts at byte position: %d\n", kidValueStart)
	fmt.Println(pkDigestHex)
	fmt.Println(string(headerJSON[kidValueStart:kidValueEnd]))

	isLast := (len(headerJSON) - 2) == kidValueEnd

	// Simulate the circuit logic
	CircuitB64Kid(signerKey.PublicKey, headerB64, kidValueStart, kidValueEnd, isLast)

}

func CircuitB64Kid(pk ecdsa.PublicKey, headerB64 string, kidValueStart, kidValueEnd int, isLast bool) {
	/*
		Input to the circuit will be:

		- headerB64
		- kidValueStart
		- public key

		Logic:

		- compute the public key digest
		- hex encode the public key digest
		- determine the prefix to the public key:
		    - every character is ASCII encoded (8 bits)
			- every base64 char represents a chunk of 6 bits
			- depending on the position of a string (key-value pair) we want to check, if it's an element of JSON, the base64 chunks can:
			  - match
			  - can be offset by 2 or 6

			in summary:

			r = position_start * 8 % 6
			if 2: position_start--
			if 4: position_start-=2

			r = position_end * 8 % 6
			if 2: position_end+=2
			if 4: position_end++

			if we fallow this approach, we can

			- prepend/append the additional chars as needed
			- encode the prepended/appended key-value pair
			- do string comparison of the 2 encoded strings

			See the notes for better explanation
	*/

	// Public key to bytes
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), pk.X, pk.Y)

	// Hash the encoded public key
	pkDigest := sha256.Sum256(pubKeyBytes)

	// public key to hex
	pkDigestHex := hex.EncodeToString(pkDigest[:])

	// we're ignoring the edge cases
	fmt.Println("start:", kidValueStart)
	fmt.Println("end:", kidValueEnd)

	r := (kidValueStart * 8) % 6
	switch r {
	case 2:
		pkDigestHex = `"` + pkDigestHex
	case 4:
		pkDigestHex = `:"` + pkDigestHex
	}

	r = (kidValueEnd * 8) % 6
	switch r {
	case 2:
		if isLast {
			pkDigestHex = pkDigestHex + `"}`
		} else {
			pkDigestHex = pkDigestHex + `",`
		}
	case 4:
		pkDigestHex = pkDigestHex + `"`
	}

	fmt.Println(pkDigestHex)

	// to base64
	pkB64 := base64.RawURLEncoding.EncodeToString([]byte(pkDigestHex))
	fmt.Println(pkB64)
	fmt.Println(headerB64)

	// check if pkB64 is in the header
	ok := strings.Contains(headerB64, pkB64)
	if !ok {
		panic("public key not found")
	}

}

func TestJWSCircuit(t *testing.T) {
	// == create dummy data ==
	// 1. Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// 2. Create JWS header
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWS",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal header: %v", err))
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 3. Create JWS payload
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

	// 7. Create the complete JWS
	signatureBytes := append(common.PadTo32Bytes(r.Bytes()), common.PadTo32Bytes(s.Bytes())...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signatureBytes)
	jwtToken := signingInput + "." + signatureB64

	fmt.Println("Generated JWS:", jwtToken)
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
		circuitTemplate := &csv.CircuitJWS{
			JWSProtected: make([]uints.U8, len(headerB64)),
			JWSPayload:   make([]uints.U8, len(payloadB64)),
			CertTBSDER:   make([]uints.U8, len(tbsCert)),
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
	assignment := &csv.CircuitJWS{
		// Private inputs
		JWSProtected:  common.StringToU8Array(headerB64),
		JWSSigR:       emulated.ValueOf[Secp256r1Fr](r),
		JWSSigS:       emulated.ValueOf[Secp256r1Fr](s),
		SignerPubKeyX: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		CertTBSDER:    common.BytesToU8Array(tbsCert),
		CertSigR:      emulated.ValueOf[Secp256r1Fr](certSig.R),
		CertSigS:      emulated.ValueOf[Secp256r1Fr](certSig.S),

		// Public input
		JWSPayload:  common.StringToU8Array(payloadB64),
		QTSPPubKeyX: emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.X),
		QTSPPubKeyY: emulated.ValueOf[Secp256r1Fp](qtspKey.PublicKey.Y),
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// Create witness
	fmt.Println("\n--- Creating Witness ---")
	startWitness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	witnessTime := time.Since(startWitness)
	fmt.Printf("[OK] Witness created successfully! (took %v)\n", witnessTime)

	// Generate proof
	fmt.Println("\n--- Generating Proof ---")
	startProof := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	proofTime := time.Since(startProof)
	fmt.Printf("[OK] Proof generated successfully! (took %v)\n", proofTime)

	// Extract public witness for verification
	fmt.Println("\n--- Extracting Public Witness ---")
	startPublic := time.Now()
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	publicTime := time.Since(startPublic)
	fmt.Printf("[OK] Public witness extracted! (took %v)\n", publicTime)

	// Verify proof
	fmt.Println("\n--- Verifying Proof ---")
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic("❌ Verification failed: " + err.Error())
	}
	verifyTime := time.Since(startVerify)
	fmt.Printf("[OK] Proof verified successfully! (took %v)\n", verifyTime)

	// Summary
	fmt.Println("\n=== Performance Summary ===")
	fmt.Printf("Circuit creation:  %v\n", circuitTime)
	fmt.Printf("Witness creation:  %v\n", witnessTime)
	fmt.Printf("Proof generation:  %v\n", proofTime)
	fmt.Printf("Public extraction: %v\n", publicTime)
	fmt.Printf("Verification:      %v\n", verifyTime)
	fmt.Printf("Total time:        %v\n", witnessTime+proofTime+publicTime+verifyTime)

}
