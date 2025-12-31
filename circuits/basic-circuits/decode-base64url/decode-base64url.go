// Package decodeb64 contains ZK circuit that decodes a base64url encoded content
package decodeb64

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
	MaxBytes    = 64 // Maximum size of decoded bytes (plaintext)
	MaxBytesB64 = 86 // Maximum size of base64url encoded bytes (ceiling(64 * 4/3) = 86)
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
Decode BASE64URL defines a zero-knowledge circuit that performs base64url 
decoding inside the circuit and compares the decoded result with secret bytes.

Use case: Many credential formats have base64url encoded content.
`

// Circuit (Compare Bytes BASE64URL Circuit) defines the zero-knowledge
// circuit that performs base64url decoding inside the circuit and compares the
// decoded result with secret bytes.
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// SecretBytes contains the secret (private) input as decoded bytes
	// This is the expected plaintext value that we want to prove matches
	// the base64url encoded public input
	SecretBytes [MaxBytes]uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// PublicBytes contains the public input as base64url encoded bytes
	// (still in encoded form). The circuit will decode this and compare
	// it to the secret bytes
	PublicBytes [MaxBytesB64]uints.U8 `gnark:",public"`
}

// Define implements the circuit logic for base64url decode and compare
// This function is called by the gnark framework to build the constraint system
//
// In this circuit, we prove: "I know SecretBytes (plaintext) such that
// DecodeBase64Url(PublicBytes) == SecretBytes"
func (c *Circuit) Define(api frontend.API) error {
	// Step 1: Decode the base64url encoded public input inside the circuit
	// This creates constraints that verify correct base64url decoding
	decodedBytes, err := zkcore.DecodeBase64Url(api, c.PublicBytes[:])
	if err != nil {
		return fmt.Errorf("failed to decode base64url in circuit: %w", err)
	}

	// Step 2: Compare the decoded bytes with the secret input bytes
	// This proves that we know the plaintext (secret) that matches the
	// base64url encoded public input
	zkcore.AssertIsEqualBytes(api, c.SecretBytes[:], decodedBytes)

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs - base64url encoded plaintext
	SecretBytes string

	// Public inputs - base64url encoded data (stays encoded)
	PublicBytes string
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate secret bytes (will be decoded)
	sBuf, err := base64.RawURLEncoding.DecodeString(w.SecretBytes)
	if err != nil {
		return fmt.Errorf("failed to decode secret input: %w", err)
	}
	if len(sBuf) > MaxBytes {
		return fmt.Errorf("decoded secret input exceeds max size: got %d bytes, max %d",
			len(sBuf), MaxBytes)
	}

	// Validate public bytes (stays encoded, so check encoded length)
	if len(w.PublicBytes) > MaxBytesB64 {
		return fmt.Errorf("encoded public input exceeds max size: got %d bytes, max %d",
			len(w.PublicBytes), MaxBytesB64)
	}

	// Verify public bytes is valid base64url (optional sanity check)
	_, err = base64.RawURLEncoding.DecodeString(w.PublicBytes)
	if err != nil {
		return fmt.Errorf("public input is not valid base64url: %w", err)
	}

	return nil
}

// CreateWitness creates a new witness for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode the secret input (private witness)
	sBuf, err := base64.RawURLEncoding.DecodeString(w.SecretBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret input: %w", err)
	}

	// Public input stays encoded
	pBuf := []byte(w.PublicBytes)

	// Convert to U8 arrays with padding
	sBuf8, err := zkcore.BytesToU8ArrayWithPadding(sBuf, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert secret bytes: %w", err)
	}

	pBuf8, err := zkcore.BytesToU8ArrayWithPadding(pBuf, MaxBytesB64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public bytes: %w", err)
	}

	// Copy to fixed-size arrays
	var sb [MaxBytes]uints.U8
	var pb [MaxBytesB64]uints.U8
	copy(sb[:], sBuf8)
	copy(pb[:], pBuf8)

	return &Circuit{
		SecretBytes: sb,
		PublicBytes: pb,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Public input stays encoded
	pBuf := []byte(w.PublicBytes)

	// Create empty secret bytes (not used in verification)
	sBuf8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty secret bytes: %w", err)
	}

	pBuf8, err := zkcore.BytesToU8ArrayWithPadding(pBuf, MaxBytesB64)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public bytes: %w", err)
	}

	var sb [MaxBytes]uints.U8
	var pb [MaxBytesB64]uints.U8
	copy(sb[:], sBuf8)
	copy(pb[:], pBuf8)

	return &Circuit{
		SecretBytes: sb,
		PublicBytes: pb,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit
// This data is known only to the prover
type PrivateInput struct {
	// Bytes contains base64url encoded plaintext data
	// This will be decoded before circuit execution and represents the secret
	// value that should match the public input after in-circuit decoding
	Bytes string `json:"bytes" description:"BASE64URL encoded plaintext (decoded before proving)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// Bytes contains base64url encoded data that will be decoded inside the circuit
	// This remains encoded and the circuit proves correct decoding
	Bytes string `json:"bytes" description:"BASE64URL encoded data (decoded in-circuit)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"bytes": {
		Max:         MaxBytes,
		Description: "Maximum decoded byte size",
	},
	"encoded_bytes": {
		Max:         MaxBytesB64,
		Description: "Maximum base64url encoded byte size",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (base64url encoded)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (plaintext, base64url encoded)"`
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
type VerifyRequest struct {
	Public PublicInput `json:"public" description:"Public ZK circuit inputs (must match prove request)"`
	Proof  string      `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// VerifyResponse defines the response body from the verify endpoint
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
type API struct{}

// Parse converts JSON-encoded public and private inputs into a circuit instance
func (api *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse the JSON inputs
	var publicInput PublicInput
	var privateInput PrivateInput

	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// Handle verification case (no private input)
	if privateInputJSON == nil {
		w := WitnessInput{
			PublicBytes: publicInput.Bytes,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 2: Create witness with validation
	w := WitnessInput{
		SecretBytes: privateInput.Bytes,
		PublicBytes: publicInput.Bytes,
	}

	// Validate inputs
	if err := w.Validate(); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	return w.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit with the framework
var Info = &circuits.CircuitInfo{
	// Name is the circuit identifier used in API routes
	Name: "decode-base64url",

	// Description explains what this circuit proves
	Description: "Proves knowledge of plaintext that corresponds to base64url encoded public input. The circuit decodes the public input in-circuit and compares it with the secret plaintext.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &Circuit{
		SecretBytes: [MaxBytes]uints.U8{},
		PublicBytes: [MaxBytesB64]uints.U8{},
	},

	// InputParser converts JSON API requests into circuit inputs
	InputParser: &API{},

	// EndpointInfo defines API documentation
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
