package models

import "github.com/consensys/gnark/backend/groth16"

// ZKCircuitRegistry provides a trusted source for verifying keys
type ZKCircuitRegistry interface {
	// Get retrieves a circuit by name
	Get(name string) (Circuit, error)
	// GetById retrieves a circuit by id
	GetById(name string) (Circuit, error)
	// List lists circuits by name
	List() []string
	// Register registers a new ZK Circuit
	Register(circuit Circuit) error

	// GetVerifyingKey retrieves a verifying key by its hash
	GetVerifyingKey(keyHash string) (groth16.VerifyingKey, error)
	// RegisterVerifyingKey stores a verifying key and returns its hash
	RegisterVerifyingKey(vk groth16.VerifyingKey, circuitID string) (string, error)
}

// Circuits provides information about the ZK Circuit
type Circuit interface {
	// Returns circuit information
	Info() CircuitInfo
	// Returns Proving Keys
	ProvingKey()
	// Returns JSON schema of the public inputs
	GetPublicInputs()
	// Returns JSON schema of the secret inputs
	GetSecretInputs()
}

type CircuitInfo struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Integrity string `json:"integrity"`
	Data      []byte `json:"data"` // base64 encoded circuit
}

// GnarkCircuit instantiation of a Circuit for the Gnark ZK system
type GnarkCircuit struct {
}
