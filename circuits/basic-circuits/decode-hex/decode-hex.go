// Package decodehex contains hex decoding ZK circuits
package decodehex

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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
	MaxDecodedBytes = 128 // Maximum size of decoded bytes (plaintext)
	MaxEncodedBytes = 256 // Maximum size of hex encoded bytes (2 * MaxDecodedBytes)
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
CircuitHex defines a zero-knowledge circuit that performs hexadecimal decoding 
inside the circuit and compares the decoded result with secret bytes.

IMPORTANT: The circuit ONLY supports lowercase hex characters (0-9, a-f). 
Uppercase hex characters will cause the circuit to fail.

IMPORTANT: the inputs must be padded correctly with 0s, else decoding fails as it expects fixed-size inputs with hex characters

Use case: Many credential formats use hex encoding to encode bytes.

The circuit:
1. Takes a public hex-encoded string (e.g., "48656c6c6f" for "Hello")
2. Decodes it inside the circuit to get the plaintext bytes (lowercase hex only)
3. Compares the decoded bytes with the secret plaintext input
4. Proves equality without revealing the secret bytes

This verifies correct hex decoding as part of the zero-knowledge proof.
`

// CircuitHex decodes a public hex encoded byte string and asserts equality
// with the private byte string
type CircuitHex struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// Bytes is the secret plaintext bytes that we want to keep private
	// This is the decoded form that should match the hex-encoded public input
	Bytes [MaxDecodedBytes]uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// BytesHex is the public hex-encoded input (still in encoded form)
	// The circuit will decode this and compare it to the secret Bytes
	BytesHex [MaxEncodedBytes]uints.U8 `gnark:",public"`
}

// Define defines the logic of the circuit for hex decode and compare
//
// In this circuit, we prove: "I know Bytes (plaintext) such that:
//
//	DecodeHex(BytesHex) == Bytes"
func (c *CircuitHex) Define(api frontend.API) error {
	// Step 1: Decode the hex-encoded public input inside the circuit
	// This creates constraints that verify correct hex decoding
	decodedBytes, err := zkcore.DecodeHex(api, c.BytesHex[:])
	if err != nil {
		return fmt.Errorf("failed to decode hex in circuit: %w", err)
	}

	// Step 2: Assert equality between the decoded bytes and secret input
	// This proves we know the plaintext that matches the hex-encoded public input
	zkcore.AssertIsEqualBytes(api, c.Bytes[:], decodedBytes)

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs - hex encoded plaintext
	Bytes string // Hex string (will be decoded for secret witness)

	// Public inputs - hex encoded data (stays encoded)
	BytesHex string // Hex string (stays encoded for circuit to decode)
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate secret bytes (decode to check validity and size)
	secretBytes, err := hex.DecodeString(w.Bytes)
	if err != nil {
		return fmt.Errorf("failed to decode secret bytes: %w", err)
	}
	if len(secretBytes) > MaxDecodedBytes {
		return fmt.Errorf("decoded secret bytes exceed max size: got %d bytes, max %d",
			len(secretBytes), MaxDecodedBytes)
	}

	// Validate public hex bytes (check encoded length)
	cleanHex := w.BytesHex
	if len(cleanHex) > MaxEncodedBytes*2 {
		return fmt.Errorf("hex encoded public bytes exceed max size: got %d chars, max %d",
			len(cleanHex), MaxEncodedBytes*2)
	}

	// Verify it's valid hex
	publicBytes, err := hex.DecodeString(w.BytesHex)
	if err != nil {
		return fmt.Errorf("public bytes is not valid hex: %w", err)
	}

	// Verify that secret bytes match decoded public bytes
	if len(secretBytes) != len(publicBytes) {
		return fmt.Errorf("length mismatch: secret has %d bytes, public decodes to %d bytes",
			len(secretBytes), len(publicBytes))
	}
	for i := range secretBytes {
		if secretBytes[i] != publicBytes[i] {
			return fmt.Errorf("byte mismatch at position %d: secret and decoded public don't match", i)
		}
	}

	return nil
}

// CreateWitness creates a new witness for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode the secret input (private witness)
	secretBytes, err := hex.DecodeString(w.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret bytes: %w", err)
	}

	// Public input: keep as hex-encoded ASCII bytes
	// The circuit will decode this during constraint generation
	publicHexBytes := []byte(w.BytesHex)

	// Convert to U8 arrays with padding
	secretU8, err := zkcore.BytesToU8ArrayWithPadding(secretBytes, MaxDecodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert secret bytes: %w", err)
	}

	publicU8, err := zkcore.BytesToU8ArrayWithPadding(publicHexBytes, MaxEncodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public hex bytes: %w", err)
	}

	// Copy to fixed-size arrays
	var secretArray [MaxDecodedBytes]uints.U8
	var publicArray [MaxEncodedBytes]uints.U8
	copy(secretArray[:], secretU8)
	copy(publicArray[:], publicU8)

	return &CircuitHex{
		Bytes:    secretArray,
		BytesHex: publicArray,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Public input: hex-encoded ASCII bytes
	cleanHex := w.BytesHex
	publicHexBytes := []byte(cleanHex)

	// Create empty secret bytes (not used in verification)
	secretU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxDecodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty secret bytes: %w", err)
	}

	publicU8, err := zkcore.BytesToU8ArrayWithPadding(publicHexBytes, MaxEncodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public hex bytes: %w", err)
	}

	// Copy to fixed-size arrays
	var secretArray [MaxDecodedBytes]uints.U8
	var publicArray [MaxEncodedBytes]uints.U8
	copy(secretArray[:], secretU8)
	copy(publicArray[:], publicU8)

	return &CircuitHex{
		Bytes:    secretArray,
		BytesHex: publicArray,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit
// This data is known only to the prover
type PrivateInput struct {
	// Bytes contains hex-encoded plaintext data
	// IMPORTANT: Must be lowercase hex only (0-9, a-f). Uppercase will fail.
	// This will be decoded before circuit execution (secret witness)
	// Example: "48656c6c6f" for "Hello" (lowercase only!)
	Bytes string `json:"bytes" description:"Lowercase hex-encoded plaintext bytes (decoded before proving, must be 0-9 a-f only)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// BytesHex contains hex-encoded data that will be decoded inside the circuit
	// IMPORTANT: Must be lowercase hex only (0-9, a-f). Uppercase will fail.
	// This remains encoded and the circuit proves correct decoding
	// Example: "48656c6c6f" for "Hello" (lowercase only!)
	BytesHex string `json:"bytes_hex" description:"Lowercase hex-encoded data (decoded in-circuit, must be 0-9 a-f only)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"bytes": {
		Max:         MaxDecodedBytes,
		Description: "Maximum decoded byte size",
	},
	"bytes_hex": {
		Max:         MaxEncodedBytes,
		Description: "Maximum hex-encoded byte size (2x decoded size)",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (hex-encoded)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (plaintext, hex-encoded)"`
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

	bHex := publicInput.BytesHex
	if len(bHex) < MaxEncodedBytes {
		bHex += strings.Repeat("0", MaxEncodedBytes-len(bHex))
	}

	// Handle verification case (no private input)
	if privateInputJSON == nil {
		w := WitnessInput{
			BytesHex: bHex,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	pHex := privateInput.Bytes
	if len(pHex) < MaxEncodedBytes {
		pHex += strings.Repeat("0", MaxEncodedBytes-len(pHex))
	}

	// Step 2: Create witness with validation
	w := WitnessInput{
		Bytes:    pHex,
		BytesHex: bHex,
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
	Name: "decode-hex",

	// Description explains what this circuit proves
	Description: "Proves knowledge of plaintext bytes that correspond to hex-encoded public input (lowercase hex only: 0-9, a-f). The circuit decodes the hex input in-circuit and compares it with the secret plaintext.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &CircuitHex{
		Bytes:    [MaxDecodedBytes]uints.U8{},
		BytesHex: [MaxEncodedBytes]uints.U8{},
	},

	// InputParser converts JSON API requests into circuit inputs
	InputParser: &API{},

	// EndpointInfo defines OpenAPI/Swagger documentation
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
