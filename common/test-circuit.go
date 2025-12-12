package common

import (
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Init circuit initializes a circuit
func InitCircut(ccsPath, pkPath, vkPath string, forceCompile bool, circuitTemplate frontend.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	if forceCompile {
		os.Remove(ccsPath)
		os.Remove(pkPath)
		os.Remove(vkPath)
	}

	if _, err := os.Stat(pkPath); os.IsNotExist(err) || forceCompile {
		fmt.Println("compiling the circuit")

		if err := SetupAndSave(circuitTemplate, ccsPath, pkPath, vkPath); err != nil {
			panic(err)
		}
		// Load what we just saved
		return LoadSetup(ccsPath, pkPath, vkPath)
	} else {
		// Subsequent runs: just load
		return LoadSetup(ccsPath, pkPath, vkPath)
	}

}

// TestCircuit executes witness and proof creation, and verification. The function times the real function time of execution
func TestCircuit(assignment frontend.Circuit, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) {

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
	fmt.Printf("Witness creation:  %v\n", witnessTime)
	fmt.Printf("Proof generation:  %v\n", proofTime)
	fmt.Printf("Public extraction: %v\n", publicTime)
	fmt.Printf("Verification:      %v\n", verifyTime)
	fmt.Printf("Total time:        %v\n", witnessTime+proofTime+publicTime+verifyTime)

}
