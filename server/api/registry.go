package api

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/common"
)

// CircuitRegistry stores compiled circuits by name
type CircuitRegistry struct {
	dir      string // circuit directory
	circuits map[string]*Circuit
}

type Circuit struct {
	Instance *CircuitInstance
	Info     *circuits.CircuitInfo
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

// LoadCircuit loads the circuit from a file
func (cr CircuitRegistry) LoadCircuit(ci *circuits.CircuitInfo) error {

	// TODO: if circuits are not loaded, circuit path info will be incorrect
	ci.Dir = cr.dir
	csPath, pkPath, vkPath := ci.FilePaths()
	fmt.Println("path:", csPath)

	// load the setup
	cs, pk, vk, err := common.LoadSetup(csPath, pkPath, vkPath)
	if err != nil {
		return fmt.Errorf("failed to load the circuit: %v", err)
	}

	return cr.Register(ci.Name, &Circuit{
		Instance: &CircuitInstance{
			CS:           cs,
			ProvingKey:   pk,
			VerifyingKey: vk,
			InputParser:  ci.InputParser,
		},
		Info: ci,
	})
}

// NewCircuitRegistry creates a new registry
func NewCircuitRegistry(dir string) (*CircuitRegistry, error) {
	// Create a new circuit
	cr := &CircuitRegistry{
		dir:      dir,
		circuits: make(map[string]*Circuit),
	}

	// load known circuits
	err := cr.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load circuits: %v", err)
	}

	return cr, nil
}

// Get returns a circuit by name
func (cr *CircuitRegistry) Get(name string) (*Circuit, error) {
	if c, ok := cr.circuits[name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("circuit %s not found", name)
}

// Register registers a new circuit by user-defined name
func (cr *CircuitRegistry) Register(name string, circuit *Circuit) error {
	if _, ok := cr.circuits[name]; ok {
		return fmt.Errorf("circuit with name %s already exists", name)
	}
	cr.circuits[name] = circuit
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

	info, ok := CircuitList[name]
	if !ok {
		return fmt.Errorf("circuit not on the list")
	}
	fmt.Printf("[OK] Loaded pre-compiled setup for %s\n", name)
	return cr.Register(name, &Circuit{
		Instance: &CircuitInstance{
			CS:           ccs,
			ProvingKey:   pk,
			VerifyingKey: vk,
			InputParser:  info.InputParser,
		},
		Info: info,
	})
}
