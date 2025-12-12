package common

import (
	"fmt"
	"os"

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
