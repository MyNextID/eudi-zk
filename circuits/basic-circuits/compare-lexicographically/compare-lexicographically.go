// Package comparelex contains lexicographical comparison ZK circuits
package comparelex

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

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
	MaxStringBytes = 256 // Maximum size for each string input
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
CircuitLex defines a zero-knowledge circuit that proves lexicographical 
ordering between two strings without revealing one of them.

Use case: Prove that a secret string comes before (or after) a public string 
in alphabetical/lexicographical order, without revealing the secret string 
itself. This is useful for privacy-preserving comparisons such as proving age 
ranges, name ordering, or other sorted data relationships.

The circuit performs byte-by-byte lexicographical comparison:
- Returns 1 if StringA < StringB (A comes before B)
- Returns 0 if StringA >= StringB (A comes after or equals B)

Both strings are assumed to be UTF-8 encoded. The comparison follows standard 
lexicographical ordering rules where bytes are compared from left to right 
until a difference is found or one string ends.
`

// CircuitLex performs a lexicographical comparison between two byte strings
// Assumptions: inputs are UTF-8 encoded strings
type CircuitLex struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// StringA is the secret reference string that will be compared
	// This value is NOT revealed in the proof
	StringA [MaxStringBytes]uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// StringB is the public comparison string
	// The verifier knows this string and wants to verify the relationship with StringA
	StringB [MaxStringBytes]uints.U8 `gnark:",public"`

	// Result is the expected comparison result (1 if StringA < StringB, 0 otherwise)
	// The prover must prove they know StringA such that the comparison yields this result
	Result frontend.Variable `gnark:",public"`
}

// Define defines the circuit logic for lexicographical comparison
//
// In this circuit, we prove: "I know StringA such that:
//
//	IsSmaller(StringB, StringA) == Result"
//
// Where IsSmaller(B, A) returns 1 if B < A lexicographically, 0 otherwise
func (c *CircuitLex) Define(api frontend.API) error {
	// Perform lexicographical comparison: check if StringB < StringA
	// Returns 1 if StringB comes before StringA, 0 otherwise
	comparisonResult, err := zkcore.IsSmaller(api, c.StringB[:], c.StringA[:])
	if err != nil {
		return fmt.Errorf("failed to perform lexicographical comparison: %w", err)
	}

	// Assert that the computed result matches the expected public result
	// This proves the prover knows a StringA that produces the claimed ordering
	api.AssertIsEqual(comparisonResult, c.Result)

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	StringA string // UTF-8 string

	// Public inputs
	StringB string            // UTF-8 string
	Result  frontend.Variable // Comparison result (0 or 1)
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate StringA
	aBytes := []byte(w.StringA)
	if len(aBytes) > MaxStringBytes {
		return fmt.Errorf("StringA exceeds max size: got %d bytes, max %d",
			len(aBytes), MaxStringBytes)
	}
	if !utf8.Valid(aBytes) {
		return fmt.Errorf("StringA is not valid UTF-8")
	}

	// Validate StringB
	bBytes := []byte(w.StringB)
	if len(bBytes) > MaxStringBytes {
		return fmt.Errorf("StringB exceeds max size: got %d bytes, max %d",
			len(bBytes), MaxStringBytes)
	}
	if !utf8.Valid(bBytes) {
		return fmt.Errorf("StringB is not valid UTF-8")
	}

	// Validate Result (must be 0 or 1)
	// Note: Result is frontend.Variable, so we can't validate its actual value
	// here
	// The circuit will enforce the constraint during proving

	return nil
}

// CreateWitness creates a new witness for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode strings
	aBytes := []byte(w.StringA)
	bBytes := []byte(w.StringB)

	// Convert to U8 arrays with padding
	aU8, err := zkcore.BytesToU8ArrayWithPadding(aBytes, MaxStringBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert StringA: %w", err)
	}
	bU8, err := zkcore.BytesToU8ArrayWithPadding(bBytes, MaxStringBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert StringB: %w", err)
	}

	// Copy to fixed-size arrays
	var aArray [MaxStringBytes]uints.U8
	var bArray [MaxStringBytes]uints.U8
	copy(aArray[:], aU8)
	copy(bArray[:], bU8)

	return &CircuitLex{
		StringA: aArray,
		StringB: bArray,
		Result:  w.Result,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Decode StringB
	bBytes := []byte(w.StringB)

	// Create empty StringA (not used in verification)
	aU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxStringBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty StringA: %w", err)
	}

	bU8, err := zkcore.BytesToU8ArrayWithPadding(bBytes, MaxStringBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert StringB: %w", err)
	}

	// Copy to fixed-size arrays
	var aArray [MaxStringBytes]uints.U8
	var bArray [MaxStringBytes]uints.U8
	copy(aArray[:], aU8)
	copy(bArray[:], bU8)

	return &CircuitLex{
		StringA: aArray,
		StringB: bArray,
		Result:  w.Result,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit
// This data is known only to the prover
type PrivateInput struct {
	// StringA contains the secret UTF-8 encoded string
	StringA string `json:"string" description:"UTF-8 string (secret)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// StringB contains the public UTF-8 encoded string
	StringB string `json:"string" description:"UTF-8 string (public)"`

	// Result is the expected comparison result
	// 1 if StringA < StringB (A comes before B lexicographically)
	// 0 if StringA >= StringB (A comes after or equals B)
	Result int `json:"result" description:"Expected comparison result: 1 if StringA < StringB, 0 otherwise"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"string": {
		Max:         MaxStringBytes,
		Description: "Maximum string size in bytes (UTF-8 encoded)",
	},
	"result": {
		Min:         0,
		Max:         1,
		Description: "Comparison result (0 or 1)",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (StringB and expected result)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (StringA)"`
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

	// Validate result value
	if publicInput.Result != 0 && publicInput.Result != 1 {
		return nil, fmt.Errorf("result must be 0 or 1, got %d", publicInput.Result)
	}

	// Handle verification case (no private input)
	if privateInputJSON == nil {
		w := WitnessInput{
			StringB: publicInput.StringB,
			Result:  publicInput.Result,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 2: Create witness with validation
	w := WitnessInput{
		StringA: privateInput.StringA,
		StringB: publicInput.StringB,
		Result:  publicInput.Result,
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
	Name: "compare-lex",

	// Description explains what this circuit proves
	Description: "Proves lexicographical ordering relationship between a secret string and a public string without revealing the secret. Returns 1 if secret < public, 0 otherwise.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &CircuitLex{
		StringA: [MaxStringBytes]uints.U8{},
		StringB: [MaxStringBytes]uints.U8{},
		Result:  0,
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
