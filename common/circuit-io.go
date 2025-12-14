package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Save compiled circuit and keys
func SetupAndSave(circuitTemplate frontend.Circuit, ccsPath, pkPath, vkPath string) error {
	fmt.Println("\n--- Compiling Circuit ---")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuitTemplate)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Circuit compiled: %d constraints\n", ccs.GetNbConstraints())

	// Save compiled circuit
	ccsFile, err := os.Create(ccsPath)
	if err != nil {
		return err
	}
	defer ccsFile.Close()
	if _, err := ccs.WriteTo(ccsFile); err != nil {
		return err
	}

	fmt.Println("\n--- Running Setup ---")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}

	// Save proving key
	pkFile, err := os.Create(pkPath)
	if err != nil {
		return err
	}
	defer pkFile.Close()
	if _, err := pk.WriteTo(pkFile); err != nil {
		return err
	}

	// Save verification key
	vkFile, err := os.Create(vkPath)
	if err != nil {
		return err
	}
	defer vkFile.Close()
	if _, err := vk.WriteTo(vkFile); err != nil {
		return err
	}

	fmt.Println("✓ Setup completed and saved!")
	return nil
}

// Load pre-compiled circuit and keys
func LoadSetup(ccsPath, pkPath, vkPath string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	// Load constraint system
	ccsFile, err := os.Open(ccsPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer ccsFile.Close()

	ccs := groth16.NewCS(ecc.BN254)
	if _, err := ccs.ReadFrom(ccsFile); err != nil {
		return nil, nil, nil, err
	}

	// Load proving key
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return nil, nil, nil, err
	}

	// Load verification key
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, nil, err
	}

	fmt.Println("✓ Loaded pre-compiled setup")
	return ccs, pk, vk, nil
}

func validatePath(path string) error {
	// Get the current working directory (execution directory)
	baseDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Clean the input path
	cleanPath := filepath.Clean(path)

	// Reject absolute paths (they bypass base directory entirely)
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Resolve to absolute path within base directory
	absPath := filepath.Join(baseDir, cleanPath)

	// Verify the path is still within base directory
	relPath, err := filepath.Rel(baseDir, absPath)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// Check if relative path escapes (starts with ..)
	if strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || relPath == ".." {
		return fmt.Errorf("path escapes base directory: %s", path)
	}

	// Optional but recommended: Check symlinks
	if evalPath, err := filepath.EvalSymlinks(absPath); err == nil {
		evalRel, err := filepath.Rel(baseDir, evalPath)
		if err != nil || strings.HasPrefix(evalRel, ".."+string(filepath.Separator)) || evalRel == ".." {
			return fmt.Errorf("path escapes via symlink: %s", path)
		}
	}

	return nil
}

// ensureDirectories creates all parent directories for the given file paths
func ensureDirectories(paths ...string) error {
	for _, path := range paths {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && !info.IsDir()
}

// safeRemove removes a file only if it exists and after thorough validation
func safeRemove(path string) error {
	// Validate path is within allowed directory
	if err := validatePath(path); err != nil {
		return err
	}

	// Get working directory for joining
	baseDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Create full path
	fullPath := filepath.Join(baseDir, filepath.Clean(path))

	// Lstat (don't follow symlinks) to check what we're actually removing
	info, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist - this is fine, nothing to remove
			return nil
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Security check: Ensure it's a regular file, not a symlink or directory
	if !info.Mode().IsRegular() {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to remove symlink: %s", path)
		}
		if info.Mode().IsDir() {
			return fmt.Errorf("refusing to remove directory: %s", path)
		}
		return fmt.Errorf("refusing to remove special file: %s", path)
	}

	//Check file ownership/permissions
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && stat.Uid != uint32(os.Getuid()) {
		// Only remove files owned by current user
		return fmt.Errorf("refusing to remove file not owned by process: %s", path)
	}

	// Final validation right before removal
	if err := validatePath(path); err != nil {
		return err
	}

	// Remove the file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to remove file %s: %w", path, err)
	}

	return nil
}
