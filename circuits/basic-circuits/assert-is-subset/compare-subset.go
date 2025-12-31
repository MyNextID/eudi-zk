// Package assertissubset asserts that a subset exists within a larger byte array
package assertissubset

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
	MaxBytes       = 256
	MaxSubsetBytes = 128
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
AssertIsSubset defines a zero-knowledge circuit that proves a subset of bytes
exists within a larger secret byte array at a specific position, without
revealing the full byte array or the position.

Use case: Prove that specific data exists within a larger secret dataset
without revealing the complete dataset or where the data is located.
`

// Circuit defines the circuit input parameters
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// Bytes is the private full byte array that contains the subset
	// This value is NOT revealed in the proof
	Bytes [MaxBytes]uints.U8 `gnark:",secret"`

	// BytesSize is the actual length of the Bytes array before padding
	// This value is NOT revealed in the proof
	BytesSize frontend.Variable `gnark:",secret"`

	// PositionStart is the secret starting position where the subset begins
	// This value is NOT revealed in the proof
	PositionStart frontend.Variable `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// Subset is the public byte array that we prove exists in Bytes
	// This is visible to everyone
	Subset [MaxSubsetBytes]uints.U8 `gnark:",public"`

	// SubsetSize is the actual length of the Subset array before padding
	// This value is NOT revealed in the proof
	SubsetSize frontend.Variable `gnark:",secret"`
}

// Define implements the circuit logic that will be converted into constraints
// This is the core of the zero-knowledge proof - what we're actually proving
//
// In this circuit, we prove: "I know Bytes and PositionStart such that
// Subset exists in Bytes starting at PositionStart"
func (c *Circuit) Define(api frontend.API) error {
	// Assert that the subset exists within the bytes at the given position
	// This creates arithmetic constraints that enforce the subset relationship
	// If the subset doesn't match at the position, proof generation will fail
	zkcore.AssertIsSubsetWithPadding(api, c.Bytes[:], c.BytesSize, c.Subset[:], c.SubsetSize, c.PositionStart)
	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	Bytes         string
	PositionStart int

	// Public inputs
	Subset string
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate Bytes
	bytesBuf, err := base64.RawURLEncoding.DecodeString(w.Bytes)
	if err != nil {
		return fmt.Errorf("failed to decode the bytes input: %v", err)
	}
	if len(bytesBuf) > MaxBytes {
		return fmt.Errorf("bytes input must be at most %d, got %d", MaxBytes, len(bytesBuf))
	}

	// Validate Subset
	subsetBuf, err := base64.RawURLEncoding.DecodeString(w.Subset)
	if err != nil {
		return fmt.Errorf("failed to decode the subset input: %v", err)
	}
	if len(subsetBuf) > MaxSubsetBytes {
		return fmt.Errorf("subset input must be at most %d, got %d", MaxSubsetBytes, len(subsetBuf))
	}

	// Validate PositionStart
	if w.PositionStart+len(subsetBuf) > len(bytesBuf) {
		return fmt.Errorf("subset extends beyond bytes array: position %d + subset length %d > bytes length %d",
			w.PositionStart, len(subsetBuf), len(bytesBuf))
	}

	return nil
}

// CreateWitness creates a new witness
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode bytes
	bytesBuf, err := base64.RawURLEncoding.DecodeString(w.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the bytes input: %v", err)
	}

	// Decode subset
	subsetBuf, err := base64.RawURLEncoding.DecodeString(w.Subset)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the subset input: %v", err)
	}

	// Store actual sizes before padding
	bytesSize := len(bytesBuf)
	subsetSize := len(subsetBuf)

	// Convert to U8 arrays with padding
	bytesU8, err := zkcore.BytesToU8ArrayWithPadding(bytesBuf, MaxBytes)
	if err != nil {
		return nil, err
	}
	subsetU8, err := zkcore.BytesToU8ArrayWithPadding(subsetBuf, MaxSubsetBytes)
	if err != nil {
		return nil, err
	}

	// Copy to fixed-size arrays
	var bytes [MaxBytes]uints.U8
	var subset [MaxSubsetBytes]uints.U8
	copy(bytes[:], bytesU8)
	copy(subset[:], subsetU8)

	return &Circuit{
		Bytes:         bytes,
		BytesSize:     bytesSize,
		PositionStart: w.PositionStart,
		Subset:        subset,
		SubsetSize:    subsetSize,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Decode subset
	subsetBuf, err := base64.RawURLEncoding.DecodeString(w.Subset)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the subset input: %v", err)
	}

	// Store actual subset size before padding
	subsetSize := len(subsetBuf)

	// Create empty bytes array
	bytesU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxBytes)
	if err != nil {
		return nil, err
	}

	// Convert subset to U8 array with padding
	subsetU8, err := zkcore.BytesToU8ArrayWithPadding(subsetBuf, MaxSubsetBytes)
	if err != nil {
		return nil, err
	}

	// Copy to fixed-size arrays
	var bytes [MaxBytes]uints.U8
	var subset [MaxSubsetBytes]uints.U8
	copy(bytes[:], bytesU8)
	copy(subset[:], subsetU8)

	return &Circuit{
		Bytes:         bytes,
		BytesSize:     0, // Default value for public witness
		PositionStart: 0, // Default value for public witness
		Subset:        subset,
		SubsetSize:    subsetSize,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs sent via API
// This data is known only to the prover
type PrivateInput struct {
	// Bytes contains base64url encoded bytes that remain secret
	Bytes string `json:"bytes" description:"BASE64URL encoded full byte array (secret witness)"`

	// PositionStart is the secret starting position of the subset
	PositionStart int `json:"position_start" description:"Starting position where subset begins (secret)"`
}

// PublicInput defines the JSON structure for public inputs sent via API
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// Subset contains base64url encoded bytes that will be publicly visible
	Subset string `json:"subset" description:"BASE64URL encoded subset byte array (public)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"bytes": {
		Max: MaxBytes,
	},
	"subset": {
		Max: MaxSubsetBytes,
	},
	"position_start": {
		Max: MaxBytes - 1,
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
	// Success indicates if the verification process completed
	Success string `json:"success"`

	// Valid indicates if the proof is mathematically valid
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

	// Unmarshal public input JSON
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// If no private input, create public witness only
	if privateInputJSON == nil {
		w := WitnessInput{
			Subset: publicInput.Subset,
		}
		return w.CreatePublicWitness()
	}

	// Unmarshal private input JSON
	var privateInput PrivateInput
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Create witness input
	w := WitnessInput{
		Bytes:         privateInput.Bytes,
		PositionStart: privateInput.PositionStart,
		Subset:        publicInput.Subset,
	}

	// Validate before creating witness
	if err := w.Validate(); err != nil {
		return nil, fmt.Errorf("witness validation failed: %w", err)
	}

	return w.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit with the framework
// This enables automatic API endpoint generation
var Info = &circuits.CircuitInfo{
	// Name is the circuit identifier used in API routes
	Name: "assert-is-subset",

	// Description explains what this circuit proves in plain language
	Description: "Proves that a public subset exists within a secret byte array at a secret position, without revealing the full array or position.",

	LongDescription: DescriptionLong,

	// Version enables API versioning and backward compatibility
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &Circuit{
		Bytes:         [MaxBytes]uints.U8{},
		BytesSize:     0,
		PositionStart: 0,
		Subset:        [MaxSubsetBytes]uints.U8{},
		SubsetSize:    0,
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
