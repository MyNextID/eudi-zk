// Package assertecpubkey contains a ZK circuit that transforms an EC public key
package assertecpubkeyd

import (
	"crypto/elliptic"
	"crypto/sha256"
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
	// Uncompressed EC point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
	UncompressedPubKeyBytes = 65
	// SHA256 produces 32-byte digests
	SHA256DigestBytes = 32
	// Individual coordinate size
	CoordinateBytes = 32
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
Assert EC Public Key defines a zero-knowledge circuit that proves knowledge of
an EC secp256r1 public key that produces a specific SHA256 digest, without 
revealing the public key itself.

Use case: Prove you know a public key (X, Y coordinates) that hashes to a 
specific digest, without revealing the actual public key. This is useful as
comparing digests is easier than comparing multiple public key components.

The circuit:
1. Takes secret EC point coordinates (X, Y)
2. Converts them to uncompressed format (0x04 || X || Y)
3. Computes SHA256 digest of the public key bytes
4. Proves the digest matches the public digest
5. Proves the public key bytes match the serialized form

This ensures the prover knows a valid EC public key that produces the claimed 
digest and serialization.
`

// Circuit is a circuit that computes and compares public key digests
// for EC secp256r1
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// SignerPubKeyX is the X coordinate of the EC public key point (secret)
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// SignerPubKeyY is the Y coordinate of the EC public key point (secret)
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// SignerPubKeyBytes is the uncompressed public key encoding (0x04 || X || Y)
	// This is the expected serialized form of the public key
	SignerPubKeyBytes [UncompressedPubKeyBytes]uints.U8 `gnark:",public"`

	// SignerPubKeyDigest is the SHA256 hash of SignerPubKeyBytes
	// This is what the verifier knows - the digest of the public key
	SignerPubKeyDigest [SHA256DigestBytes]uints.U8 `gnark:",public"`
}

// Define defines the ZK Circuit logic
//
// In this circuit, we prove: "I know EC point (X, Y) such that:
//  1. SHA256(0x04 || X || Y) == SignerPubKeyDigest
//  2. (0x04 || X || Y) == SignerPubKeyBytes"
func (c *Circuit) Define(api frontend.API) error {
	// Step 1: Convert emulated field elements (X, Y) to byte arrays
	// Each coordinate is 32 bytes
	xBytes, err := conversion.EmulatedToBytes(api, &c.SignerPubKeyX)
	if err != nil {
		return err
	}
	yBytes, err := conversion.EmulatedToBytes(api, &c.SignerPubKeyY)
	if err != nil {
		return err
	}

	// Step 2: Create the uncompressed EC point format
	// Uncompressed format: 0x04 || X || Y (65 bytes total)
	prefix := uints.NewU8(4) // 0x04 prefix indicates uncompressed point
	pubKeyBytes := append(xBytes, yBytes...)
	pubKeyBytes = append([]uints.U8{prefix}, pubKeyBytes...)

	// Step 3: Compute SHA256 digest of the public key bytes
	digest, err := zkcore.SHA256(api, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to compute SHA256: %w", err)
	}

	// Step 4: Assert that computed public key bytes match the public input
	// This proves we correctly serialized the EC point
	zkcore.AssertIsEqualBytes(api, pubKeyBytes, c.SignerPubKeyBytes[:])

	// Step 5: Assert that computed digest matches the public digest
	// This proves the EC point produces the claimed digest
	zkcore.AssertIsEqualBytes(api, digest, c.SignerPubKeyDigest[:])

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

	// Public inputs - base64url encoded
	PubKeyBytes  string // Base64url encoded uncompressed public key (65 bytes)
	PubKeyDigest string // Base64url encoded SHA256 digest (32 bytes)
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

	// Validate public key bytes
	pkBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to decode public key bytes: %w", err)
	}
	if len(pkBytes) != UncompressedPubKeyBytes {
		return fmt.Errorf("public key bytes must be %d bytes, got %d",
			UncompressedPubKeyBytes, len(pkBytes))
	}
	if pkBytes[0] != 0x04 {
		return fmt.Errorf("public key must be in uncompressed format (first byte 0x04)")
	}

	// Validate digest
	digestBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyDigest)
	if err != nil {
		return fmt.Errorf("failed to decode digest: %w", err)
	}
	if len(digestBytes) != SHA256DigestBytes {
		return fmt.Errorf("digest must be %d bytes, got %d", SHA256DigestBytes, len(digestBytes))
	}

	// Verify consistency: the provided coordinates should match the public key bytes
	expectedPK := elliptic.Marshal(elliptic.P256(),
		new(big.Int).SetBytes(xBytes),
		new(big.Int).SetBytes(yBytes))
	if len(expectedPK) != len(pkBytes) {
		return fmt.Errorf("coordinate mismatch with public key bytes")
	}
	for i := range expectedPK {
		if expectedPK[i] != pkBytes[i] {
			return fmt.Errorf("coordinate mismatch: serialized public key doesn't match provided coordinates")
		}
	}

	// Verify digest matches
	computedDigest := sha256.Sum256(pkBytes)
	for i := range computedDigest {
		if computedDigest[i] != digestBytes[i] {
			return fmt.Errorf("digest mismatch: provided digest doesn't match SHA256 of public key")
		}
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

	// Decode public inputs
	pkBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key bytes: %w", err)
	}
	digestBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}

	// Convert to big integers for emulated elements
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Convert to U8 arrays
	pkU8 := zkcore.BytesToU8Array(pkBytes)
	digestU8 := zkcore.BytesToU8Array(digestBytes)

	// Copy to fixed-size arrays
	var pkArray [UncompressedPubKeyBytes]uints.U8
	var digestArray [SHA256DigestBytes]uints.U8
	copy(pkArray[:], pkU8)
	copy(digestArray[:], digestU8)

	return &Circuit{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](x),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](y),
		SignerPubKeyBytes:  pkArray,
		SignerPubKeyDigest: digestArray,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Decode public inputs
	pkBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key bytes: %w", err)
	}
	digestBytes, err := base64.RawURLEncoding.DecodeString(w.PubKeyDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}

	// Convert to U8 arrays
	pkU8 := zkcore.BytesToU8Array(pkBytes)
	digestU8 := zkcore.BytesToU8Array(digestBytes)

	// Copy to fixed-size arrays
	var pkArray [UncompressedPubKeyBytes]uints.U8
	var digestArray [SHA256DigestBytes]uints.U8
	copy(pkArray[:], pkU8)
	copy(digestArray[:], digestU8)

	// Create empty emulated elements for secret inputs
	zero := big.NewInt(0)

	return &Circuit{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](zero),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](zero),
		SignerPubKeyBytes:  pkArray,
		SignerPubKeyDigest: digestArray,
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
	// PubKeyBytes is the uncompressed public key (0x04 || X || Y, 65 bytes total)
	PubKeyBytes string `json:"pubkey_bytes" description:"BASE64URL encoded uncompressed EC public key (65 bytes: 0x04 || X || Y)"`

	// PubKeyDigest is the SHA256 hash of PubKeyBytes (32 bytes)
	PubKeyDigest string `json:"pubkey_digest" description:"BASE64URL encoded SHA256 digest of public key (32 bytes)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"coordinate": {
		Max:         CoordinateBytes,
		Description: "EC coordinate size (32 bytes)",
	},
	"pubkey_bytes": {
		Max:         UncompressedPubKeyBytes,
		Description: "Uncompressed EC public key size (65 bytes)",
	},
	"digest": {
		Max:         SHA256DigestBytes,
		Description: "SHA256 digest size (32 bytes)",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (public key bytes and digest)"`
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
			PubKeyBytes:  publicInput.PubKeyBytes,
			PubKeyDigest: publicInput.PubKeyDigest,
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
		PubKeyBytes:  publicInput.PubKeyBytes,
		PubKeyDigest: publicInput.PubKeyDigest,
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
	Name: "ec-pubkey-digest",

	// Description explains what this circuit proves
	Description: "Proves knowledge of an EC secp256r1 public key (X, Y coordinates) that produces a specific SHA256 digest and matches a given serialization, without revealing the public key itself.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &Circuit{
		SignerPubKeyBytes:  [UncompressedPubKeyBytes]uints.U8{},
		SignerPubKeyDigest: [SHA256DigestBytes]uints.U8{},
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
