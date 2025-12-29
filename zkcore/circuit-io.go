// Package zkcore contains common ZK circuit functions
package zkcore

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Compile compiles a circuit and returns the constraint system
func Compile(circuit *frontend.Circuit, opts ...frontend.CompileOption) (*constraint.ConstraintSystem, error) {

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, *circuit, opts...)
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// SetupAndSave compiles and stores a circuit
func SetupAndSave(circuitTemplate frontend.Circuit, ccsPath, pkPath, vkPath string) error {
	fmt.Println("\n--- Compiling Circuit ---")
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuitTemplate)
	if err != nil {
		return err
	}
	fmt.Printf("[OK] Circuit compiled: %d constraints\n", ccs.GetNbConstraints())

	// Save compiled circuit
	ccsFile, err := SecureCreate(ccsPath)
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
	pkFile, err := SecureCreate(pkPath)
	if err != nil {
		return err
	}
	defer pkFile.Close()
	if _, err := pk.WriteTo(pkFile); err != nil {
		return err
	}

	// Save verification key
	vkFile, err := SecureCreate(vkPath)
	if err != nil {
		return err
	}
	defer vkFile.Close()
	if _, err := vk.WriteTo(vkFile); err != nil {
		return err
	}

	fmt.Println("[OK] Setup completed and saved!")
	return nil
}

// LoadSetup loads compiled ZK files
func LoadSetup(ccsPath, pkPath, vkPath string) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	// Load constraint system
	ccsFile, err := SecureOpen(ccsPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer ccsFile.Close()

	ccs := groth16.NewCS(ecc.BN254)
	if _, err := ccs.ReadFrom(ccsFile); err != nil {
		return nil, nil, nil, err
	}

	// Load proving key
	pkFile, err := SecureOpen(pkPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return nil, nil, nil, err
	}

	// Load verification key
	vkFile, err := SecureOpen(vkPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return nil, nil, nil, err
	}

	fmt.Println("[OK] Loaded pre-compiled setup")
	return ccs, pk, vk, nil
}

// validatePath validates that a path is safe to use (stays within working directory)
func validatePath(path string) error {
	// Get the current working directory (execution directory)
	baseDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	return validatePathWithBase(path, baseDir)
}

// validatePathWithBase validates a path against a specific base directory
func validatePathWithBase(path, baseDir string) error {
	// Check for empty path
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	// Clean the input path
	cleanPath := filepath.Clean(path)

	// Reject absolute paths (they bypass base directory entirely)
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Get absolute base directory
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("failed to resolve base directory: %w", err)
	}

	// Resolve to absolute path within base directory
	absPath := filepath.Join(absBase, cleanPath)

	// Verify the path is still within base directory
	relPath, err := filepath.Rel(absBase, absPath)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// Check if relative path escapes (starts with ..)
	if strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || relPath == ".." {
		return fmt.Errorf("path escapes base directory: %s", path)
	}

	// Optional but recommended: Check symlinks
	if evalPath, err := filepath.EvalSymlinks(absPath); err == nil {
		evalRel, err := filepath.Rel(absBase, evalPath)
		if err != nil || strings.HasPrefix(evalRel, ".."+string(filepath.Separator)) || evalRel == ".." {
			return fmt.Errorf("path escapes via symlink: %s", path)
		}
	}

	return nil
}

// getValidatedPath returns the validated absolute path
func getValidatedPath(path string) (string, error) {
	if err := validatePath(path); err != nil {
		return "", err
	}

	baseDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	return filepath.Join(baseDir, filepath.Clean(path)), nil
}

// ensureDirectories creates all parent directories for the given file paths
func ensureDirectories(paths ...string) error {
	for _, path := range paths {
		if err := validatePath(path); err != nil {
			return fmt.Errorf("invalid path %s: %w", path, err)
		}

		dir := filepath.Dir(path)
		validDir, err := getValidatedPath(dir)
		if err != nil {
			return err
		}

		// #nosec G301 -- 0750 is intentionally chosen for directory permissions
		if err := os.MkdirAll(validDir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(path string) (bool, error) {
	if err := validatePath(path); err != nil {
		return false, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return false, err
	}

	info, err := os.Stat(validPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}

// safeRemove removes a file only if it exists and after thorough validation
func safeRemove(path string) error {
	// Validate path is within allowed directory
	if err := validatePath(path); err != nil {
		return err
	}

	// Get validated full path
	fullPath, err := getValidatedPath(path)
	if err != nil {
		return err
	}

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

	// Check file ownership/permissions on Unix systems
	if runtime.GOOS != "windows" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		uid := os.Getuid()
		// #nosec G115 -- uid is always >= 0 on Unix systems where this code runs
		if uid >= 0 && ok && stat.Uid != uint32(uid) {
			// Only remove files owned by current user
			return fmt.Errorf("refusing to remove file not owned by process: %s", path)
		}
	}

	// Remove the file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to remove file %s: %w", path, err)
	}

	return nil
}

// SecureOpen opens a file for reading with path validation
func SecureOpen(path string) (*os.File, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by validatePath
	return os.Open(validPath)
}

// SecureCreate creates a file for writing with path validation and secure permissions
func SecureCreate(path string) (*os.File, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	// Ensure parent directories exist
	if err := ensureDirectories(path); err != nil {
		return nil, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return nil, err
	}

	// Create with secure permissions (0600 = rw-------)
	// #nosec G304 -- path validated by validatePath
	return os.OpenFile(validPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
}

// SecureOpenFile opens a file with custom flags and permissions after validation
func SecureOpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by validatePath
	return os.OpenFile(validPath, flag, perm)
}

// SecureWriteFile writes data to a file with path validation
func SecureWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := validatePath(path); err != nil {
		return err
	}

	// Ensure parent directories exist
	if err := ensureDirectories(path); err != nil {
		return err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return err
	}

	// #nosec G306 -- caller controls permissions intentionally
	return os.WriteFile(validPath, data, perm)
}

// SecureReadFile reads data from a file with path validation
func SecureReadFile(path string) ([]byte, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by validatePath
	return os.ReadFile(validPath)
}

// SecureAppend opens a file for appending with path validation
func SecureAppend(path string) (*os.File, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	// Ensure parent directories exist
	if err := ensureDirectories(path); err != nil {
		return nil, err
	}

	validPath, err := getValidatedPath(path)
	if err != nil {
		return nil, err
	}

	// #nosec G304 -- path validated by validatePath
	return os.OpenFile(validPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}
