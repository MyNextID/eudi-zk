package common

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Initializes a circuit. If forceCompile is true, it ignores the local cache and overwrites it. Make sure you set `forceRecompile = true` if you're making any changes to the circuit.
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
		log.Fatalf("witness creation failed: %v", err)
	}
	witnessTime := time.Since(startWitness)
	fmt.Printf("[OK] Witness created successfully! (took %v)\n", witnessTime)

	// Generate proof
	fmt.Println("\n--- Generating Proof ---")
	startProof := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("proof creation failed: %v", err)
	}
	proofTime := time.Since(startProof)
	fmt.Printf("[OK] Proof generated successfully! (took %v)\n", proofTime)

	// Extract public witness for verification
	fmt.Println("\n--- Extracting Public Witness ---")
	startPublic := time.Now()
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("public witness extraction failed: %v", err)
	}
	publicTime := time.Since(startPublic)
	fmt.Printf("[OK] Public witness extracted! (took %v)\n", publicTime)

	// Verify proof
	fmt.Println("\n--- Verifying Proof ---")
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("verification failed: %v", err)
	}
	verifyTime := time.Since(startVerify)
	fmt.Printf("[OK] Proof verified successfully! (took %v)\n", verifyTime)

	// Summary
	fmt.Println("\n=== Performance Summary ===")
	fmt.Printf("Witness creation:  %v\n", witnessTime)
	fmt.Printf("Proof generation:  %v\n", proofTime)
	fmt.Printf("Public extraction: %v\n", publicTime)
	fmt.Printf("Verification:      %v\n", verifyTime)
	fmt.Printf("Total time:        %v\n", witnessTime+proofTime+publicTime+verifyTime)
}

// ==== TestCircuit function v2 ====
// refactor the function and the results

// CircuitTestResult holds timing, size, and result information
type CircuitTestResult struct {
	WitnessTime       time.Duration
	ProofTime         time.Duration
	PublicTime        time.Duration
	VerifyTime        time.Duration
	TotalTime         time.Duration
	WitnessSize       int // in bytes
	PublicWitnessSize int // in bytes
	ProofSize         int // in bytes
	Success           bool
	Error             error
}

// CircuitTestOptions configures test execution behaviour
type CircuitTestOptions struct {
	Verbose     bool
	Writer      io.Writer
	FailOnError bool
	SkipVerify  bool
}

// DefaultTestOptions returns sensible defaults
func DefaultTestOptions() *CircuitTestOptions {
	return &CircuitTestOptions{
		Verbose:     true,
		Writer:      os.Stdout,
		FailOnError: true,
		SkipVerify:  false,
	}
}

// TestCircuit executes witness and proof creation, and verification with detailed timing
func TestCircuitV2(
	assignment frontend.Circuit,
	ccs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	vk groth16.VerifyingKey,
	opts *CircuitTestOptions,
) *CircuitTestResult {
	if opts == nil {
		opts = DefaultTestOptions()
	}

	result := &CircuitTestResult{Success: false}
	startTotal := time.Now()

	logf := func(format string, args ...interface{}) {
		if opts.Verbose && opts.Writer != nil {
			fmt.Fprintf(opts.Writer, format, args...)
		}
	}

	handleError := func(stage string, err error) bool {
		result.Error = fmt.Errorf("%s failed: %w", stage, err)
		if opts.FailOnError {
			log.Fatal(result.Error)
		}
		logf("[FAIL] %v\n", result.Error)
		return false
	}

	// Create witness
	logf("\n--- Creating Witness ---\n")
	startWitness := time.Now()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	result.WitnessTime = time.Since(startWitness)

	if err != nil {
		handleError("witness creation", err)
		return result
	}

	// Measure witness size
	var witnessBuf bytes.Buffer
	if _, err := witness.WriteTo(&witnessBuf); err == nil {
		result.WitnessSize = witnessBuf.Len()
	}

	logf("[OK] Witness created successfully! (took %v, size: %s)\n",
		result.WitnessTime, formatBytes(result.WitnessSize))

	// Generate proof
	logf("\n--- Generating Proof ---\n")
	startProof := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	result.ProofTime = time.Since(startProof)

	if err != nil {
		handleError("proof generation", err)
		return result
	}

	// Measure proof size
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err == nil {
		result.ProofSize = proofBuf.Len()
	}

	logf("[OK] Proof generated successfully! (took %v, size: %s)\n",
		result.ProofTime, formatBytes(result.ProofSize))

	// Extract public witness
	logf("\n--- Extracting Public Witness ---\n")
	startPublic := time.Now()
	publicWitness, err := witness.Public()
	result.PublicTime = time.Since(startPublic)

	if err != nil {
		handleError("public witness extraction", err)
		return result
	}

	// Measure public witness size
	var publicBuf bytes.Buffer
	if _, err := publicWitness.WriteTo(&publicBuf); err == nil {
		result.PublicWitnessSize = publicBuf.Len()
	}

	logf("[OK] Public witness extracted! (took %v, size: %s)\n",
		result.PublicTime, formatBytes(result.PublicWitnessSize))

	// Verify proof (optional)
	if !opts.SkipVerify {
		logf("\n--- Verifying Proof ---\n")
		startVerify := time.Now()
		err = groth16.Verify(proof, vk, publicWitness)
		result.VerifyTime = time.Since(startVerify)

		if err != nil {
			handleError("verification", err)
			return result
		}
		logf("[OK] Proof verified successfully! (took %v)\n", result.VerifyTime)
	}

	result.TotalTime = time.Since(startTotal)
	result.Success = true

	// Summary
	if opts.Verbose {
		logf("\n=== Performance Summary ===\n")
		logf("Witness creation:  %v (size: %s)\n", result.WitnessTime, formatBytes(result.WitnessSize))
		logf("Proof generation:  %v (size: %s)\n", result.ProofTime, formatBytes(result.ProofSize))
		logf("Public extraction: %v (size: %s)\n", result.PublicTime, formatBytes(result.PublicWitnessSize))
		if !opts.SkipVerify {
			logf("Verification:      %v\n", result.VerifyTime)
		}
		logf("Total time:        %v\n", result.TotalTime)
		logf("\n=== Size Summary ===\n")
		logf("Full witness:      %s\n", formatBytes(result.WitnessSize))
		logf("Public witness:    %s\n", formatBytes(result.PublicWitnessSize))
		logf("Proof:             %s\n", formatBytes(result.ProofSize))
	}

	return result
}

// formatBytes converts bytes to human-readable format
func formatBytes(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// TestCircuitSimple is a convenience wrapper with default options
func TestCircuitSimple(
	assignment frontend.Circuit,
	ccs constraint.ConstraintSystem,
	pk groth16.ProvingKey,
	vk groth16.VerifyingKey,
) *CircuitTestResult {
	return TestCircuitV2(assignment, ccs, pk, vk, nil)
}

// Usage:
//
// Standard usage with defaults:
//   result := TestCircuitSimple(assignment, ccs, pk, vk)
//   if !result.Success {
//       log.Printf("Test failed: %v", result.Error)
//   }
//
// Custom options:
//   opts := &CircuitTestOptions{
//       Verbose: false,
//       FailOnError: false,
//       SkipVerify: true,
//   }
//   result := TestCircuit(assignment, ccs, pk, vk, opts)
//   if !result.Success {
//       log.Printf("Test failed: %v", result.Error)
//   }
