package common

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

func InitCircuit(ccsPath, pkPath, vkPath string, forceCompile bool, circuitTemplate frontend.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	// Validate paths to prevent directory traversal attacks
	if err := validatePath(ccsPath); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid ccsPath: %w", err)
	}
	if err := validatePath(pkPath); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid pkPath: %w", err)
	}
	if err := validatePath(vkPath); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid vkPath: %w", err)
	}

	// Create all necessary subdirectories
	if err := ensureDirectories(ccsPath, pkPath, vkPath); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create directories: %w", err)
	}

	if forceCompile {
		// Safe removal with path validation
		if err := safeRemove(ccsPath); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to remove ccsPath: %w", err)
		}
		if err := safeRemove(pkPath); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to remove pkPath: %w", err)
		}
		if err := safeRemove(vkPath); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to remove vkPath: %w", err)
		}
	}

	// Check if all files exist
	allFilesExist := fileExists(ccsPath) && fileExists(pkPath) && fileExists(vkPath)

	if !allFilesExist || forceCompile {
		fmt.Println("compiling the circuit")
		if err := SetupAndSave(circuitTemplate, ccsPath, pkPath, vkPath); err != nil {
			return nil, nil, nil, fmt.Errorf("setup and save failed: %w", err)
		}
		// Load what we just saved
		return LoadSetup(ccsPath, pkPath, vkPath)
	}

	// All files exist: just load
	return LoadSetup(ccsPath, pkPath, vkPath)
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
