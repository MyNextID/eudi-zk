// Package assertecpubkey contains EC public key assertion ZK circuits
package assertecpubkey

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/conversion"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/zkcore"
)

// ========================================================================
// CIRCUIT CONSTANTS
// ========================================================================

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

// Circuit input sizes
const (
	// EC coordinate size for P-256 curve (32 bytes per coordinate)
	CoordinateBytes = 32
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
CircuitPK defines a zero-knowledge circuit that proves knowledge of EC secp256r1
public key coordinates (X, Y) that match specific byte representations, without 
revealing the coordinates themselves.

The circuit:
1. Takes secret EC point coordinates (X, Y) as emulated field elements
2. Converts each coordinate to its 32-byte big-endian representation
3. Compares the byte representations with public expected values
4. Proves equality without revealing the secret coordinates

This ensures the prover knows EC coordinates that serialize to the claimed byte 
representations.
`

// CircuitPK defines a circuit that converts public key elements to byte strings
// and asserts equality with the provided byte string representation
type CircuitPK struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// SignerPubKeyX is the X coordinate of the EC public key point (secret)
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// SignerPubKeyY is the Y coordinate of the EC public key point (secret)
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// SignerPubKeyXBytes is the expected X coordinate as bytes (32 bytes, big-endian)
	SignerPubKeyXBytes [CoordinateBytes]uints.U8 `gnark:",public"`

	// SignerPubKeyYBytes is the expected Y coordinate as bytes (32 bytes, big-endian)
	SignerPubKeyYBytes [CoordinateBytes]uints.U8 `gnark:",public"`
}

// Define defines the circuit logic
//
// In this circuit, we prove: "I know EC coordinates (X, Y) such that:
//
//	ToBytes(X) == SignerPubKeyXBytes AND
//	ToBytes(Y) == SignerPubKeyYBytes"
func (c *CircuitPK) Define(api frontend.API) error {
	// Step 1: Convert emulated field element X to bytes
	xBytes, err := conversion.EmulatedToBytes(api, &c.SignerPubKeyX)
	if err != nil {
		return fmt.Errorf("failed to convert X coordinate to bytes: %w", err)
	}

	// Step 2: Convert emulated field element Y to bytes
	yBytes, err := conversion.EmulatedToBytes(api, &c.SignerPubKeyY)
	if err != nil {
		return fmt.Errorf("failed to convert Y coordinate to bytes: %w", err)
	}

	// Step 3: Assert that X bytes match the public expected X bytes
	zkcore.AssertIsEqualBytes(api, xBytes, c.SignerPubKeyXBytes[:])

	// Step 4: Assert that Y bytes match the public expected Y bytes
	zkcore.AssertIsEqualBytes(api, yBytes, c.SignerPubKeyYBytes[:])

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs - base64url encoded coordinates
	PubKeyX string // Base64url encoded X coordinate (32 bytes)
	PubKeyY string // Base64url encoded Y coordinate (32 bytes)

	// Public inputs - base64url encoded byte representations
	PubKeyXBytes string // Base64url encoded expected X bytes (32 bytes)
	PubKeyYBytes string // Base64url encoded expected Y bytes (32 bytes)
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyX)
	if err != nil {
		return fmt.Errorf("failed to decode X coordinate: %w", err)
	}
	if len(xBytes) != CoordinateBytes {
		return fmt.Errorf("coordinate X must be %d bytes, got %d", CoordinateBytes, len(xBytes))
	}

	// Validate Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyY)
	if err != nil {
		return fmt.Errorf("failed to decode Y coordinate: %w", err)
	}
	if len(yBytes) != CoordinateBytes {
		return fmt.Errorf("coordinate Y must be %d bytes, got %d", CoordinateBytes, len(yBytes))
	}

	// Validate expected X bytes
	xExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyXBytes)
	if err != nil {
		return fmt.Errorf("failed to decode expected X bytes: %w", err)
	}
	if len(xExpectedBytes) != CoordinateBytes {
		return fmt.Errorf("expected X bytes must be %d bytes, got %d",
			CoordinateBytes, len(xExpectedBytes))
	}

	// Validate expected Y bytes
	yExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyYBytes)
	if err != nil {
		return fmt.Errorf("failed to decode expected Y bytes: %w", err)
	}
	if len(yExpectedBytes) != CoordinateBytes {
		return fmt.Errorf("expected Y bytes must be %d bytes, got %d",
			CoordinateBytes, len(yExpectedBytes))
	}

	// Verify that coordinates match their expected byte representations
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Convert back to bytes (big-endian) and compare
	xConverted := x.Bytes()
	yConverted := y.Bytes()

	// Pad to 32 bytes if needed (big.Int.Bytes() may return shorter slices)
	if len(xConverted) < CoordinateBytes {
		padded := make([]byte, CoordinateBytes)
		copy(padded[CoordinateBytes-len(xConverted):], xConverted)
		xConverted = padded
	}
	if len(yConverted) < CoordinateBytes {
		padded := make([]byte, CoordinateBytes)
		copy(padded[CoordinateBytes-len(yConverted):], yConverted)
		yConverted = padded
	}

	// Verify X bytes match
	for i := range xExpectedBytes {
		if xConverted[i] != xExpectedBytes[i] {
			return fmt.Errorf("coordinate X mismatch at byte %d: coordinate encodes to %02x but expected %02x",
				i, xConverted[i], xExpectedBytes[i])
		}
	}

	// Verify Y bytes match
	for i := range yExpectedBytes {
		if yConverted[i] != yExpectedBytes[i] {
			return fmt.Errorf("coordinate Y mismatch at byte %d: coordinate encodes to %02x but expected %02x",
				i, yConverted[i], yExpectedBytes[i])
		}
	}

	// Verify the point is on the P-256 curve
	if !elliptic.P256().IsOnCurve(x, y) {
		return fmt.Errorf("point (X, Y) is not on the P-256 curve")
	}

	return nil
}

// CreateWitness creates a new witness for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyX)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyY)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	// Decode expected byte representations
	xExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyXBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode expected X bytes: %w", err)
	}
	yExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyYBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode expected Y bytes: %w", err)
	}

	// Convert to big integers for emulated elements
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Convert expected bytes to U8 arrays
	xExpU8 := zkcore.BytesToU8Array(xExpectedBytes)
	yExpU8 := zkcore.BytesToU8Array(yExpectedBytes)

	// Copy to fixed-size arrays
	var xExpArray [CoordinateBytes]uints.U8
	var yExpArray [CoordinateBytes]uints.U8
	copy(xExpArray[:], xExpU8)
	copy(yExpArray[:], yExpU8)

	return &CircuitPK{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](x),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](y),
		SignerPubKeyXBytes: xExpArray,
		SignerPubKeyYBytes: yExpArray,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Decode expected byte representations
	xExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyXBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode expected X bytes: %w", err)
	}
	yExpectedBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyYBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode expected Y bytes: %w", err)
	}

	// Convert to U8 arrays
	xExpU8 := zkcore.BytesToU8Array(xExpectedBytes)
	yExpU8 := zkcore.BytesToU8Array(yExpectedBytes)

	// Copy to fixed-size arrays
	var xExpArray [CoordinateBytes]uints.U8
	var yExpArray [CoordinateBytes]uints.U8
	copy(xExpArray[:], xExpU8)
	copy(yExpArray[:], yExpU8)

	// Create empty emulated elements for secret inputs
	zero := big.NewInt(0)

	return &CircuitPK{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](zero),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](zero),
		SignerPubKeyXBytes: xExpArray,
		SignerPubKeyYBytes: yExpArray,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit
// This data is known only to the prover
type PrivateInput struct {
	// PubKeyX is the X coordinate of the EC public key (32 bytes, base64url encoded)
	PubKeyX string `json:"pubkey_x" description:"BASE64URL encoded X coordinate of EC public key (32 bytes)"`

	// PubKeyY is the Y coordinate of the EC public key (32 bytes, base64url encoded)
	PubKeyY string `json:"pubkey_y" description:"BASE64URL encoded Y coordinate of EC public key (32 bytes)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// PubKeyXBytes is the expected X coordinate as bytes (32 bytes, base64url encoded)
	PubKeyXBytes string `json:"pubkey_x_bytes" description:"BASE64URL encoded expected X coordinate bytes (32 bytes, big-endian)"`

	// PubKeyYBytes is the expected Y coordinate as bytes (32 bytes, base64url encoded)
	PubKeyYBytes string `json:"pubkey_y_bytes" description:"BASE64URL encoded expected Y coordinate bytes (32 bytes, big-endian)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"coordinate": {
		Max:         CoordinateBytes,
		Description: "EC coordinate size (32 bytes for P-256)",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (expected X and Y byte representations)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (EC coordinates X, Y)"`
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
			PubKeyXBytes: publicInput.PubKeyXBytes,
			PubKeyYBytes: publicInput.PubKeyYBytes,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 2: Create witness with validation
	w := WitnessInput{
		PubKeyX:      privateInput.PubKeyX,
		PubKeyY:      privateInput.PubKeyY,
		PubKeyXBytes: publicInput.PubKeyXBytes,
		PubKeyYBytes: publicInput.PubKeyYBytes,
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
	Name: "assert-ec-pubkey",

	// Description explains what this circuit proves
	Description: "Proves knowledge of EC secp256r1 public key coordinates (X, Y) that match specific byte representations, without revealing the coordinate values themselves.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &CircuitPK{
		SignerPubKeyXBytes: [CoordinateBytes]uints.U8{},
		SignerPubKeyYBytes: [CoordinateBytes]uints.U8{},
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
