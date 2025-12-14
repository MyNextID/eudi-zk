package ckb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	ckb "github.com/mynextid/eudi-zk/circuits/key-binding"
	"github.com/mynextid/eudi-zk/common"
)

func TestPubKeyHashCircuit_Define(t *testing.T) {
	// == create dummy data ==
	// Generate ES256 (P-256) key pair
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

	fmt.Println("Public key bytes (65):", hex.EncodeToString(pubKeyBytes))
	fmt.Println("SHA256 digest (32):", hex.EncodeToString(pkDigest[:]))
	fmt.Println("Hex string (64):", pkDigestHex)

	// Print individual bytes for comparison
	fmt.Println("\n=== SHA256 Digest Bytes ===")
	for i, b := range pkDigest {
		fmt.Printf("digest[%d] = %d (0x%02x)\n", i, b, b)
	}

	fmt.Println("\n=== Hex String Characters ===")
	for i, c := range pkDigestHex {
		fmt.Printf("hex[%d] = '%c' (ASCII %d)\n", i, c, c)
	}

	ccsPath := "compiled/kb-circuit-v1.ccs"
	pkPath := "compiled/kb-proving-v1.key"
	vkPath := "compiled/kb-verifying-v1.key"

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	forceCompile := true

	if forceCompile {
		os.Remove(ccsPath)
		os.Remove(pkPath)
		os.Remove(vkPath)
	}

	fmt.Println("\n--- Loading the circuit ---")
	startCircuit := time.Now()
	if _, err := os.Stat(pkPath); os.IsNotExist(err) || forceCompile {
		fmt.Println("compiling the circuit")
		// First time: compile and save
		circuitTemplate := &ckb.PubKeyHashCircuit{
			PubKeyHex: make([]uints.U8, len(pkDigestHex)),
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

	// Convert hex string to ASCII byte values
	pubKeyHexBytes := make([]uints.U8, len(pkDigestHex))
	for i, char := range pkDigestHex {
		// Each character in the hex string becomes its ASCII value
		pubKeyHexBytes[i] = uints.NewU8(uint8(char))
		fmt.Printf("hex[%d] = '%c' (ASCII %d) -> U8(%d)\n", i, char, char, char)
	}

	// Create witness assignment with actual values
	assignment := &ckb.PubKeyHashCircuit{
		// Private inputs
		SignerPubKeyX: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY: emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),

		// Public inputs
		PubKeyHex: common.StringToU8Array(pkDigestHex),
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
