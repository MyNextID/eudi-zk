package api

import (
	"fmt"

	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/zkcore"
)

// CircuitRegistry stores compiled circuits by name
type CircuitRegistry struct {
	dir      string // circuit directory
	circuits map[string]*circuits.Circuit
}

// LoadAll loads all the registered circuits. Note: the circuits must be compiled to be loaded correctly
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
	fmt.Println("[LOAD] loading circuit:", csPath)

	// load the setup
	cs, pk, vk, err := zkcore.LoadSetup(csPath, pkPath, vkPath)
	if err != nil {
		return fmt.Errorf("failed to load the circuit: %v", err)
	}

	return cr.Register(ci.Name, &circuits.Circuit{
		Instance: &circuits.CircuitInstance{
			CS:           &cs,
			ProvingKey:   &pk,
			VerifyingKey: &vk,
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
		circuits: make(map[string]*circuits.Circuit),
	}

	// load known circuits
	err := cr.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load circuits: %v", err)
	}

	return cr, nil
}

// Get returns a circuit by name
func (cr *CircuitRegistry) Get(name string) (*circuits.Circuit, error) {
	if c, ok := cr.circuits[name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("circuit %s not found", name)
}

// Register registers a new circuit by user-defined name
func (cr *CircuitRegistry) Register(name string, circuit *circuits.Circuit) error {
	if _, ok := cr.circuits[name]; ok {
		return fmt.Errorf("circuit with name %s already exists", name)
	}
	cr.circuits[name] = circuit
	return nil
}
