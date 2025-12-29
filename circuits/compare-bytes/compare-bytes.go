package ccb

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
// CIRCUIT DEFINITION
// ========================================================================

// CBCircuit (Compare Bytes Circuit) defines a zero-knowledge circuit that
// proves two byte arrays are equal without revealing the secret byte array.
//
// Use case: Prove you know a secret value that matches a public value, without
// revealing the secret itself.
type CBCircuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// SecretBytes is the private input - the witness that we want to keep
	// secret. This value is NOT revealed in the proof, but we prove we know it
	SecretBytes []uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// PublicBytes is the public input - visible to everyone
	// We prove that SecretBytes matches PublicBytes without revealing SecretBytes
	PublicBytes []uints.U8 `gnark:",public"`
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
	zkcore.AssertIsEqualBytes(api, c.SecretBytes, c.PublicBytes)
	return nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// CBPublicInput defines the JSON structure for public inputs sent via API
// This data will be visible to anyone verifying the proof
type CBPublicInput struct {
	// BytesB64Url contains base64url encoded bytes that will be publicly visible
	// Example: "SGVsbG8gV29ybGQ" for "Hello World"
	BytesB64Url string `json:"bytes_b64url" description:"BASE64URL encoded byte array (public)"`
}

// CBPrivateInput defines the JSON structure for private inputs sent via API
// This data is known only to the prover
type CBPrivateInput struct {
	// BytesB64Url contains base64url encoded bytes that remain secret
	// This is the witness - the secret value we're proving we know
	BytesB64Url string `json:"bytes_b64url" description:"BASE64URL encoded byte array (secret witness)"`
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// CBProveRequest defines the request body for generating a zero-knowledge proof
// The prover sends both public and private inputs to generate the proof
type CBProveRequest struct {
	Public  CBPublicInput  `json:"public" description:"Public ZK circuit inputs (visible to all)"`
	Private CBPrivateInput `json:"private" description:"Private ZK circuit inputs (secret witness)"`
}

// CBProveResponse defines the response body containing the generated proof
type CBProveResponse struct {
	// Proof is the base64url encoded zero-knowledge proof
	// This can be sent to anyone for verification without revealing the private input
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// ========================================================================
// VERIFY ENDPOINT - POST /verify
// ========================================================================

// CBVerifyRequest defines the request body for verifying a zero-knowledge proof
// The verifier only needs the public inputs and the proof (no private data)
type CBVerifyRequest struct {
	Public CBPublicInput `json:"public" description:"Public ZK circuit inputs (must match prove request)"`
	Proof  string        `json:"proof" description:"BASE64URL encoded ZK proof to verify"`
}

// CBVerifyResponse defines the response body from proof verification
type CBVerifyResponse struct {
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

// CBAPI implements the InputParser interface for this circuit
// It bridges the gap between HTTP JSON API and gnark circuit inputs
type CBAPI struct{}

// Parse converts JSON-encoded API inputs into a populated circuit instance
// This is called by the framework before proof generation
//
// Flow: JSON (API) → Decode base64url → Convert to U8 arrays → Circuit struct
func (api *CBAPI) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse JSON into Go structs
	var publicInput CBPublicInput
	var privateInput CBPrivateInput

	// Unmarshal public input JSON
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// Unmarshal private input JSON
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 2: Decode base64url strings to raw bytes
	// Both public and private inputs are decoded at the API level

	// Decode public bytes
	publicBytesDecoded, err := base64.RawURLEncoding.DecodeString(publicInput.BytesB64Url)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode public input: %w", err)
	}

	// Decode private bytes (the secret witness)
	privateBytesDecoded, err := base64.RawURLEncoding.DecodeString(privateInput.BytesB64Url)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode private input: %w", err)
	}

	// Step 3: Convert raw bytes to U8 arrays for gnark circuit
	// gnark uses uints.U8 for byte representation in circuits
	return &CBCircuit{
		SecretBytes: zkcore.BytesToU8Array(privateBytesDecoded),
		PublicBytes: zkcore.BytesToU8Array(publicBytesDecoded),
	}, nil
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// CBInfo contains all metadata needed to register this circuit with the
// framework
// This enables automatic API endpoint generation
var CBInfo = &circuits.CircuitInfo{
	// Name is the circuit identifier used in API routes
	// e.g., GET /circuits/compare-bytes, POST /prove/compare-bytes
	Name: "compare-bytes",

	// Circuit is a template instance with properly sized arrays
	// BYTE_SIZE64 indicates this circuit handles up to 64 bytes
	Circuit: &CBCircuit{
		SecretBytes: make([]uints.U8, circuits.ByteSize64),
		PublicBytes: make([]uints.U8, circuits.ByteSize64),
	},

	// Description explains what this circuit proves in plain language
	Description: "Proves equality between a secret byte array and a public byte array without revealing the secret. Both inputs are decoded from base64url before comparison.",

	// Version enables API versioning and backward compatibility
	Version: 1,

	// InputParser converts JSON API requests into circuit inputs
	InputParser: &CBAPI{},

	// EndpointInfo defines OpenAPI/Swagger documentation for auto-generated docs
	EndpointInfo: &circuits.EndpointInfo{
		Prove: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBProveRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBProveResponse{}, nil),
		},
		Verify: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBVerifyRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBVerifyResponse{}, nil),
		},
	},
}
