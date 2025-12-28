// Package ccb contains the compare-bytes ZK circuits
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

// CBB64UrlCircuit defines the zero-knowledge circuit that performs base64url
// decoding inside the circuit and compares the decoded result with secret
// bytes. This demonstrates in-circuit base64url decoding verification.
type CBB64UrlCircuit struct {
	// Bytes contains the secret (private) input as decoded bytes
	// This is the expected plaintext value that we want to prove matches the base64url encoded public input
	Bytes []uints.U8 `gnark:",secret"`

	// BytesB64 contains the public input as base64url encoded bytes (still in encoded form)
	// The circuit will decode this and compare it to the secret Bytes
	BytesB64 []uints.U8 `gnark:",public"`
}

// Define implements the circuit logic for base64url decode and compare
// This function is called by the gnark framework to build the constraint system
func (c *CBB64UrlCircuit) Define(api frontend.API) error {
	// Step 1: Decode the base64url encoded public input inside the circuit
	// This creates constraints that verify correct base64url decoding
	decodedBytes, _ := zkcore.DecodeBase64Url(api, c.BytesB64)

	// Step 2: Compare the decoded bytes with the secret input bytes
	// This proves that we know the plaintext (secret) that matches the base64url encoded public input
	zkcore.AssertIsEqualBytes(api, c.Bytes, decodedBytes)

	return nil
}

// ==== API data models ====

// CBB64UrlPublicInput defines the JSON structure for public inputs to the circuit
type CBB64UrlPublicInput struct {
	// Bytes contains base64url encoded data that will be decoded inside the circuit
	// Example: "SGVsbG8gV29ybGQ" (base64url encoding of "Hello World")
	Bytes string `json:"bytes_b64url" description:"BASE64URL encoded byte array to be decoded in-circuit"`
}

// CBB64UrlPrivateInput defines the JSON structure for private inputs to the circuit
type CBB64UrlPrivateInput struct {
	// Bytes contains base64url encoded data that will be decoded before circuit execution
	// This represents the secret value that should match the public input after decoding
	Bytes string `json:"bytes_b64url" description:"BASE64URL encoded byte array (decoded before proving)"`
}

// ==== Endpoint: /prove ====

// CBB64UrlProveRequest defines the request body for the prove endpoint
type CBB64UrlProveRequest struct {
	Public  CBB64UrlPublicInput  `json:"public" description:"Public ZK circuit inputs"`
	Private CBB64UrlPrivateInput `json:"private" description:"Private ZK circuit inputs"`
}

// CBB64UrlProveResponse defines the response body from the prove endpoint
type CBB64UrlProveResponse struct {
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// ==== Endpoint: /verify ====

// CBB64UrlVerifyRequest defines the request body for the verify endpoint
type CBB64UrlVerifyRequest struct {
	Public CBB64UrlPublicInput `json:"public" description:"Public ZK circuit inputs"`
	Proof  string              `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// CBB64UrlVerifyResponse defines the response body from the verify endpoint
type CBB64UrlVerifyResponse struct {
	Success string  `json:"success"`
	Valid   bool    `json:"valid"`
	Message *string `json:"message,omitempty"`
}

// ==== Circuit info ====

// CBB64UrlInfo contains metadata and configuration for the base64url compare circuit
// This is used by the framework to register and expose the circuit
var CBB64UrlInfo = &circuits.CircuitInfo{
	// Circuit instance with pre-sized arrays matching the expected input size
	Circuit: &CBB64UrlCircuit{
		Bytes:    make([]uints.U8, circuits.ByteSize64), // Secret decoded bytes
		BytesB64: make([]uints.U8, 86),                  // Public base64url encoded bytes
	},

	// Name identifies this circuit in the API
	Name: "compare-bytes-b64url",

	// Description explains what this circuit proves
	Description: "The circuit decodes a base64url encoded public input inside the circuit and compares it with secret decoded bytes. This proves knowledge of the plaintext corresponding to the base64url encoded data.",

	// Version for API compatibility tracking
	Version: 1,

	// InputParser handles conversion from JSON API format to circuit inputs
	InputParser: &CBB64UrlAPI{},

	// EndpointInfo defines the OpenAPI/Swagger documentation for the endpoints
	EndpointInfo: &circuits.EndpointInfo{
		Prove: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBB64UrlProveRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBB64UrlProveResponse{}, nil),
		},
		Verify: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBB64UrlVerifyRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBB64UrlVerifyResponse{}, nil),
		},
	},
}

// ==== Input parser ====

// CBB64UrlAPI implements the InputParser interface for this circuit
// It converts JSON API requests into the circuit's input format
type CBB64UrlAPI struct{}

// Parse converts JSON-encoded public and private inputs into a circuit instance
// Key difference from the first template:
// - Public input is kept as base64url encoded (decoded inside the circuit)
// - Private input is decoded here (before circuit execution)
func (p *CBB64UrlAPI) Parse(publicInput, privateInput []byte) (frontend.Circuit, error) {
	// Step 1: Parse the JSON inputs
	var pub CBB64UrlPublicInput
	var pvt CBB64UrlPrivateInput

	if err := json.Unmarshal(publicInput, &pub); err != nil {
		return nil, fmt.Errorf("failed to parse public input: %w", err)
	}

	if err := json.Unmarshal(privateInput, &pvt); err != nil {
		return nil, fmt.Errorf("failed to parse private input: %w", err)
	}

	// Step 2: Process the inputs

	// Public input: Keep as base64url encoded string (converted to bytes)
	// The circuit will decode this during constraint generation
	// This proves correct decoding as part of the zero-knowledge proof
	pubBytes := []byte(pub.Bytes)

	// Private input: Decode the base64url at the API level (before proving)
	// This is the witness value - the actual decoded bytes we're proving we know
	pvtBytes, err := base64.RawURLEncoding.DecodeString(pvt.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode the private input: %w", err)
	}

	// Step 3: Return the populated circuit with converted inputs
	return &CBB64UrlCircuit{
		Bytes:    zkcore.BytesToU8Array(pvtBytes), // Secret: decoded bytes (witness)
		BytesB64: zkcore.BytesToU8Array(pubBytes), // Public: base64url encoded bytes (still encoded)
	}, nil
}
