// Package assertisequal asserts equality of two byte arrays
package assertisequal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/zkcore"
)

// ========================================================================
// CIRCUIT CONSTANTS
// ========================================================================

// Circuit input sizes
const (
	MaxBytes = 256
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
AssertBytesEqual defines a zero-knowledge circuit that proves two byte arrays
are equal without revealing the secret byte array.

Use case: Prove you know a secret value that matches a public value, without
revealing the secret itself.
`

// CBCircuit defines the circuit input parameters
type CBCircuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// SecretBytes is the private input - the witness that we want to keep
	// secret. This value is NOT revealed in the proof, but we prove we know it
	SecretBytes [MaxBytes]uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// PublicBytes is the public input - visible to everyone
	// We prove that SecretBytes matches PublicBytes without revealing SecretBytes
	PublicBytes [MaxBytes]uints.U8 `gnark:",public"`
}

// Define implements the circuit logic that will be converted into constraints
// This is the core of the zero-knowledge proof - what we're actually proving
//
// In this circuit, we prove: "I know SecretBytes such that SecretBytes ==
// PublicBytes"
func (c *CBCircuit) Define(api frontend.API) error {
	// Assert that the secret bytes equal the public bytes
	// This creates arithmetic constraints that enforce equality
	// If the bytes don't match, proof generation will fail
	zkcore.AssertIsEqualBytes(api, c.SecretBytes[:], c.PublicBytes[:])
	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	SecretBytes string

	// Public inputs
	PublicBytes string
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {

	sBuf, err := base64.RawURLEncoding.DecodeString(w.SecretBytes)
	if err != nil {
		return fmt.Errorf("failed to decode the secret input: %v", err)
	}
	if len(sBuf) > MaxBytes {
		return fmt.Errorf("secret input must be %d, got %d", MaxBytes, len(sBuf))

	}

	pBuf, err := base64.RawURLEncoding.DecodeString(w.PublicBytes)
	if err != nil {
		return fmt.Errorf("failed to decode the secret input: %v", err)
	}
	if len(pBuf) > MaxBytes {
		return fmt.Errorf("secret input must be %d, got %d", MaxBytes, len(pBuf))

	}

	return nil
}

// CreateWitness creates a new witness
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	sBuf, err := base64.RawURLEncoding.DecodeString(w.SecretBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the secret input: %v", err)
	}
	pBuf, err := base64.RawURLEncoding.DecodeString(w.PublicBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the secret input: %v", err)
	}
	sBuf8, err := zkcore.BytesToU8ArrayWithPadding(sBuf, MaxBytes)
	if err != nil {
		return nil, err
	}
	pBuf8, err := zkcore.BytesToU8ArrayWithPadding(pBuf, MaxBytes)
	if err != nil {
		return nil, err
	}

	var sb, pb [MaxBytes]uints.U8
	copy(sb[:], sBuf8)
	copy(pb[:], pBuf8)

	return &CBCircuit{
		SecretBytes: sb,
		PublicBytes: pb,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {

	pBuf, err := base64.RawURLEncoding.DecodeString(w.PublicBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the secret input: %v", err)
	}
	sBuf8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxBytes)
	if err != nil {
		return nil, err
	}
	pBuf8, err := zkcore.BytesToU8ArrayWithPadding(pBuf, MaxBytes)
	if err != nil {
		return nil, err
	}

	var sb, pb [MaxBytes]uints.U8
	copy(sb[:], sBuf8)
	copy(pb[:], pBuf8)

	return &CBCircuit{
		SecretBytes: sb,
		PublicBytes: pb,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs sent via API
// This data is known only to the prover
type PrivateInput struct {
	// Bytes contains base64url encoded bytes that remain secret
	// This is the witness - the secret value we're proving we know
	Bytes string `json:"bytes" description:"BASE64URL encoded byte array (secret witness)"`
}

// PublicInput defines the JSON structure for public inputs sent via API
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// Bytes contains base64url encoded bytes that will be publicly visible
	// Example: "SGVsbG8gV29ybGQ" for "Hello World"
	Bytes string `json:"bytes" description:"BASE64URL encoded byte array (public)"`
}

// Constraints defines the circuit constraints
// cnf size constraint applies to the marshalled cnf JSON object
var Constraints = map[string]circuits.Constraints{
	"bytes": {
		Max: MaxBytes,
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
// The prover sends both public and private inputs to generate the proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (visible to all)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (secret witness)"`
}

// ProveResponse defines the response body containing the generated proof
type ProveResponse struct {
	// Proof is the base64url encoded zero-knowledge proof
	// This can be sent to anyone for verification without revealing the private input
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// ========================================================================
// VERIFY ENDPOINT - POST /verify
// ========================================================================

// VerifyRequest defines the request body for verifying a zero-knowledge proof
// The verifier only needs the public inputs and the proof (no private data)
type VerifyRequest struct {
	Public PublicInput `json:"public" description:"Public ZK circuit inputs (must match prove request)"`
	Proof  string      `json:"proof" description:"BASE64URL encoded ZK proof to verify"`
}

// VerifyResponse defines the response body from proof verification
type VerifyResponse struct {
	// Success indicates if the verification process completed (not if proof is valid)
	Success string `json:"success"`

	// Valid indicates if the proof is mathematically valid
	// true = the proof is correct, false = the proof is invalid or incorrect
	Valid bool `json:"valid"`

	// Message contains optional error or status information
	Message *string `json:"message,omitempty"`
}

// ========================================================================
// INPUT PARSER - Converts API JSON to circuit format
// ========================================================================

// API implements the InputParser interface for this circuit
// It bridges the gap between HTTP JSON API and gnark circuit inputs
type API struct{}

// Parse converts JSON-encoded API inputs into a populated circuit instance
// This is called by the framework before proof generation
//
// Flow: JSON (API) → Decode base64url → Convert to U8 arrays → Circuit struct
func (api *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse JSON into Go structs
	var publicInput PublicInput
	var privateInput PrivateInput

	// Unmarshal public input JSON
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	if privateInputJSON == nil {
		w := WitnessInput{
			PublicBytes: publicInput.Bytes,
		}
		return w.CreatePublicWitness()
	}

	// Unmarshal private input JSON
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}
	w := WitnessInput{
		SecretBytes: privateInput.Bytes,
		PublicBytes: publicInput.Bytes,
	}
	return w.CreateWitness()

}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit with the
// framework
// This enables automatic API endpoint generation
var Info = &circuits.CircuitInfo{
	// Name is the circuit identifier used in API routes
	// e.g., GET /circuits/compare-bytes, POST /prove/compare-bytes
	Name: "assert-is-equal",

	// Description explains what this circuit proves in plain language
	Description: "Proves equality between a secret byte array and a public byte array without revealing the secret. Both inputs are decoded from base64url before comparison.",

	LongDescription: DescriptionLong,

	// Version enables API versioning and backward compatibility
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	// BYTE_SIZE64 indicates this circuit handles up to 64 bytes
	Circuit: &CBCircuit{
		SecretBytes: [MaxBytes]uints.U8{},
		PublicBytes: [MaxBytes]uints.U8{},
	},

	// InputParser converts JSON API requests into circuit inputs
	InputParser: &API{},

	// EndpointInfo defines API documentation for auto-generated docs
	EndpointInfo: &circuits.EndpointInfo{
		Constraints: Constraints,
		Prove: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", ProveRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", ProveResponse{}, nil),
		},
		Verify: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", VerifyRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", VerifyResponse{}, nil),
		},
	},
}
