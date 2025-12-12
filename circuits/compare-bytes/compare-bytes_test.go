package ccb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	ccb "github.com/mynextid/gnark-eudi/circuits/compare-bytes"
	"github.com/mynextid/gnark-eudi/common"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

func TestComparePublicKeys(t *testing.T) {
	ccsPath := "compiled/cb-circuit-pub-key-v1.ccs"
	pkPath := "compiled/cb-proving-pub-key-v1.key"
	vkPath := "compiled/cb-verifying-pub-key-v1.key"

	forceCompile := true

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	// pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)
	publicKeyXBytes := signerKey.PublicKey.X.Bytes()
	publicKeyYBytes := signerKey.PublicKey.Y.Bytes()

	fmt.Println("\n--- Loading the circuit ---")
	startCircuit := time.Now()
	if forceCompile {
		os.Remove(ccsPath)
		os.Remove(pkPath)
		os.Remove(vkPath)
	}

	fmt.Println(len(publicKeyXBytes))
	fmt.Println(len(publicKeyYBytes))

	if _, err := os.Stat(pkPath); os.IsNotExist(err) || forceCompile {
		fmt.Println("compiling the circuit")
		// First time: compile and save
		circuitTemplate := &ccb.CircuitPK{

			SignerPubKeyXBytes: make([]uints.U8, len(publicKeyXBytes)),
			SignerPubKeyYBytes: make([]uints.U8, len(publicKeyYBytes)),
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
	assignment := &ccb.CircuitPK{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerPubKeyXBytes: common.BytesToU8Array(publicKeyXBytes),
		SignerPubKeyYBytes: common.BytesToU8Array(publicKeyYBytes),
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

func TestCompareBytes(t *testing.T) {
	ccsPath := "compiled/cb-circuit-v1.ccs"
	pkPath := "compiled/cb-proving-v1.key"
	vkPath := "compiled/cb-verifying-v1.key"

	forceCompile := true

	var ccs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey

	byteSize := 32

	randomBytes, err := GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytes2, err := GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	fmt.Println("\n--- Loading the circuit ---")
	startCircuit := time.Now()
	if forceCompile {
		os.Remove(ccsPath)
		os.Remove(pkPath)
		os.Remove(vkPath)
	}
	if _, err := os.Stat(pkPath); os.IsNotExist(err) || forceCompile {
		fmt.Println("compiling the circuit")
		// First time: compile and save
		circuitTemplate := &ccb.Circuit{
			Bytes:    make([]uints.U8, byteSize),
			PubBytes: make([]uints.U8, byteSize),
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
	assignment := &ccb.Circuit{
		// Private inputs
		Bytes: common.BytesToU8Array(randomBytes),
		// Public inputs
		// PubBytes: common.BytesToU8Array(randomBytes),
		PubBytes: common.BytesToU8Array(randomBytes),
	}
	_ = randomBytes2

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

// GenerateRandomBytes returns cryptographically secure random bytes
func GenerateRandomBytes(size int) ([]byte, error) {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}
