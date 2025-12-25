package api

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/mynextid/eudi-zk/common"
)

// CircuitRegistry stores compiled circuits by name
type CircuitRegistry struct {
	Circuits map[string]*Circuit
}

func (cr CircuitRegistry) LoadAll() error {
	for _, v := range CircuitList {
		err := cr.LoadCircuit(v)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cr CircuitRegistry) LoadCircuit(ci CircuitInfo) error {

	csPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.ccs", ci.Name, ci.Version))
	pkPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.pk", ci.Name, ci.Version))
	vkPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.vk", ci.Name, ci.Version))

	cs, pk, vk, err := common.LoadSetup(csPath, pkPath, vkPath)
	if err != nil {
		return fmt.Errorf("failed to load the circuit: %v", err)
	}

	return cr.Register(ci.Name, &Circuit{
		CS:           cs,
		ProvingKey:   pk,
		VerifyingKey: vk,
		InputParser:  ci.InputParser,
	})
}

// NewCircuitRegistry creates a new registry
func NewCircuitRegistry() *CircuitRegistry {
	return &CircuitRegistry{
		Circuits: make(map[string]*Circuit),
	}
}

// Get returns a circuit by name
func (cr *CircuitRegistry) Get(name string) (*Circuit, error) {
	if c, ok := cr.Circuits[name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("circuit %s not found", name)
}

// Register registers a new circuit by user-defined name
func (cr *CircuitRegistry) Register(name string, circuit *Circuit) error {
	if _, ok := cr.Circuits[name]; ok {
		return fmt.Errorf("circuit with name %s already exists", name)
	}
	cr.Circuits[name] = circuit
	return nil
}

// LoadSetup loads a pre-compiled circuit setup
func (cr *CircuitRegistry) LoadSetup(name, ccsPath, pkPath, vkPath string) error {
	// Load constraint system
	ccsFile, err := os.Open(ccsPath)
	if err != nil {
		return fmt.Errorf("failed to open constraint system: %w", err)
	}
	defer ccsFile.Close()

	ccs := groth16.NewCS(ecc.BN254)
	if _, err := ccs.ReadFrom(ccsFile); err != nil {
		return fmt.Errorf("failed to read constraint system: %w", err)
	}

	// Load proving key
	pkFile, err := os.Open(pkPath)
	if err != nil {
		return fmt.Errorf("failed to open proving key: %w", err)
	}
	defer pkFile.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(pkFile); err != nil {
		return fmt.Errorf("failed to read proving key: %w", err)
	}

	// Load verification key
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return fmt.Errorf("failed to open verification key: %w", err)
	}
	defer vkFile.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(vkFile); err != nil {
		return fmt.Errorf("failed to read verification key: %w", err)
	}

	fmt.Printf("[OK] Loaded pre-compiled setup for %s\n", name)
	return cr.Register(name, &Circuit{
		CS:           ccs,
		ProvingKey:   pk,
		VerifyingKey: vk,
	})
}
