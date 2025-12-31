// Package assertcnf is a ZK circuit that asserts confirmation claim (cnf) membersip within a base64url encoded JSON
package assertcnf

import (
	"bytes"
	"encoding/base64"
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
	MaxProtectedHeaderSize = 256
	MaxCnfClaimSize        = 128
	SHA256DigestSize       = 32
	SHA256HexSize          = 64 // 32 bytes * 2 hex chars per byte
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
AssertCnf circuit proves that a JWS protected header contains a specific cnf
claim with a public key digest that matches a given value, WITHOUT revealing the
full header.

Use case: Prove that a JWT contains a specific public key binding (cnf claim)
without revealing the entire JWT header or its position within the header.

cnf (Confirmation) Claim: RFC 7800 - Proof-of-Possession Key Semantics for JSON
Web Tokens (JWTs) Example cnf in JWT header: {"cnf":{"kid":"a1b2c3d4..."}}

The circuit performs these verification steps:

1. Verify that the base64url-encoded cnf is a substring of the
base64url-encoded header
2. Decode the cnf from base64url to get the JSON structure
3. Extract the hex-encoded public key digest from the decoded cnf
4. Decode the hex string to get the raw digest bytes
5. Compare the extracted digest with the provided public digest
`

// AssertCnf defines the circuit input parameters
type AssertCnf struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// ProtectedHeaderB64 is the base64url-encoded JWS protected header
	// This remains secret - we don't reveal the full header contents
	ProtectedHeaderB64 [MaxProtectedHeaderSize]uints.U8 `gnark:",secret"`
	// ProtectedHeaderSize is te actual cnf claim size without padding
	ProtectedHeaderSize frontend.Variable `gnark:",secret"`

	// CnfClaimB64 is the base64url-encoded substring containing the cnf claim
	// This is extracted from the header and proves the cnf exists at the claimed position
	CnfClaimB64 [MaxCnfClaimSize]uints.U8 `gnark:",secret"`
	// CnfClaimSize is te actual cnf claim size without padding
	CnfClaimSize frontend.Variable `gnark:",secret"`

	// CnfClaimPosition is the byte position where CnfClaimB64 starts within ProtectedHeaderB64
	// This proves we're not fabricating the cnf - it's actually in the header at this position
	CnfClaimPosition frontend.Variable `gnark:",secret"`

	// PubKeyDigestHexPosition is the byte position of the hex-encoded digest within the decoded cnf
	// After base64url decoding the cnf, this points to where the public key digest starts
	// Example: in '{"cnf":{"kid":"a1b2c3d4..."}}', points to the start of "a1b2c3d4..."
	PubKeyDigestHexPosition frontend.Variable `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// PublicKeyDigest is the SHA-256 digest of the public key we're checking for
	// This is publicly known - we prove the header contains a cnf with THIS
	// specific digest 32 bytes for SHA-256 hash
	PublicKeyDigest [SHA256DigestSize]uints.U8 `gnark:",public"`
}

// Define implements the circuit logic that proves cnf claim validity This
// creates the constraint system that will be converted into a zero-knowledge
// proof
//
// What we prove: "I know a JWS header that contains a cnf claim at a specific
// position, and when decoded, that cnf contains a public key digest matching
// the public input"
func (c *AssertCnf) Define(api frontend.API) error {
	// Step 1: Verify that CnfClaimB64 is actually contained within
	// ProtectedHeaderB64
	// This proves we're not making up a fake cnf - it must exist in the real
	// header
	// IsSubset checks: ProtectedHeaderB64[CnfClaimPosition:CnfClaimPosition+len(CnfClaimB64)] == CnfClaimB64
	zkcore.AssertIsSubsetWithPadding(api, c.ProtectedHeaderB64[:], c.ProtectedHeaderSize, c.CnfClaimB64[:], c.CnfClaimSize, c.CnfClaimPosition)

	// Step 2: Decode the base64url-encoded cnf claim to get the raw JSON bytes
	// Example: "ImNuZiI6eyJ4NXQjUzI1NiI6IjEyMzQifQ" →
	// '"cnf":{"kid":"1234"}'
	// This creates constraints that verify correct base64url decoding
	decodedCnfClaim, err := zkcore.DecodeBase64Url(api, c.CnfClaimB64[:])
	if err != nil {
		return err
	}
	// Step 3: Extract the hex-encoded public key digest from the decoded cnf
	// The digest is a SHA-256 hash hex-encoded, so it's 64 hex characters (32
	// bytes * 2)
	// Example: "a1b2c3d4e5f6..." (64 characters representing 32 bytes)
	pubKeyDigestHex := zkcore.GetSubset(api, decodedCnfClaim, c.PubKeyDigestHexPosition, SHA256HexSize)

	// Step 4: Decode the hex string to get the raw digest bytes
	// Example: "a1b2" → [0xa1, 0xb2]
	// This creates constraints that verify correct hex decoding
	extractedDigestBytes, err := zkcore.DecodeHex(api, pubKeyDigestHex)
	if err != nil {
		return err
	}

	// Step 5: Verify that the extracted digest matches the public digest
	// This is the final proof: the digest we extracted from the header equals
	// the public input
	// If they don't match, the proof generation will fail
	zkcore.AssertIsEqualBytes(api, extractedDigestBytes, c.PublicKeyDigest[:])

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	ProtectedHeader string
	CnfClaim        map[string]any

	// Public inputs
	PublicKeyDigestHex string
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate public key digest
	digestBytes, err := hex.DecodeString(w.PublicKeyDigestHex)
	if err != nil {
		return fmt.Errorf("invalid public key digest hex: %w", err)
	}
	if len(digestBytes) != SHA256DigestSize {
		return fmt.Errorf("public key digest must be %d bytes, got %d", SHA256DigestSize, len(digestBytes))
	}

	// Validate protected header is valid base64url
	if _, err := base64.RawURLEncoding.DecodeString(w.ProtectedHeader); err != nil {
		return fmt.Errorf("invalid base64url protected header: %w", err)
	}

	// Validate cnf claim exists
	if len(w.CnfClaim) == 0 {
		return fmt.Errorf("cnf claim cannot be empty")
	}

	return nil
}

// CreateWitness creates a new witness
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {

	// Step 2: Process public input - decode hex to bytes
	publicKeyDigestBytes, err := hex.DecodeString(w.PublicKeyDigestHex)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode public key digest: %w", err)
	}

	if len(publicKeyDigestBytes) != 32 {
		return nil, fmt.Errorf("public key digest must be 32 bytes (SHA-256), got %d bytes", len(publicKeyDigestBytes))
	}

	// Step 3: Encode cnf claim and trim braces to get the field content
	cnfJSON, err := json.Marshal(w.CnfClaim)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cnf claim JSON: %w", err)
	}

	// Remove outer braces: {"cnf":...} becomes "cnf":...
	cnfStr := strings.TrimPrefix(string(cnfJSON), "{")
	cnfStr = strings.TrimSuffix(cnfStr, "}")

	// Step 4: Decode the protected header to find positions
	protectedHeaderJSONBytes, err := base64.RawURLEncoding.DecodeString(w.ProtectedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the private.ProtectedHeader: %v", err)
	}

	// Step 5: Find where the cnf field appears in the protected header JSON
	cnfStart := strings.Index(string(protectedHeaderJSONBytes), cnfStr)
	if cnfStart == -1 {
		return nil, fmt.Errorf("cnf field not found in protected header JSON")
	}

	// Step 6: Align to base64 boundaries
	cnfLen := len(cnfStr)
	cnfEnd := cnfStart + cnfLen
	cnfStartAligned, cnfEndAligned := zkcore.B64Align(cnfStart, cnfEnd)

	// Extract the aligned section
	cnfAligned := protectedHeaderJSONBytes[cnfStartAligned:cnfEndAligned]

	// Step 7: Base64url encode both the full header and the aligned cnf section
	cnfAlignedB64 := base64.RawURLEncoding.EncodeToString(cnfAligned)

	// Step 8: Verify the aligned cnf appears in the base64 encoded header
	cnfB64Index := strings.Index(w.ProtectedHeader, cnfAlignedB64)
	if cnfB64Index == -1 {
		return nil, fmt.Errorf("aligned cnf not found in base64 encoded protected header")
	}

	// Step 9: Find the public key digest hex within the aligned section
	pubKeyDigestHexPosition := strings.Index(string(cnfAligned), w.PublicKeyDigestHex)
	if pubKeyDigestHexPosition == -1 {
		return nil, fmt.Errorf("public key digest hex not found in aligned cnf section")
	}

	// Step 10: Validate the digest matches
	digestHexFromCnf := string(cnfAligned)[pubKeyDigestHexPosition : pubKeyDigestHexPosition+64]
	digestBytesFromCnf, err := hex.DecodeString(digestHexFromCnf)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode digest from cnf: %w", err)
	}

	if !bytes.Equal(digestBytesFromCnf, publicKeyDigestBytes) {
		return nil, fmt.Errorf("digest mismatch: cnf digest does not match public input")
	}

	protectedB64Uints8, err := zkcore.StringToU8ArrayWithPadding(w.ProtectedHeader, MaxProtectedHeaderSize)
	if err != nil {
		return nil, fmt.Errorf("failed to map to U8: %v", err)
	}
	var p [MaxProtectedHeaderSize]uints.U8
	copy(p[:], protectedB64Uints8)

	cnfUints8, err := zkcore.StringToU8ArrayWithPadding(cnfAlignedB64, MaxCnfClaimSize)
	if err != nil {
		return nil, fmt.Errorf("failed to map to U8: %v", err)
	}
	var c [MaxCnfClaimSize]uints.U8
	copy(c[:], cnfUints8)

	pkUints8, err := zkcore.BytesToU8ArrayWithPadding(publicKeyDigestBytes, SHA256DigestSize)
	if err != nil {
		return nil, fmt.Errorf("failed to map to U8: %v", err)
	}
	var pk [SHA256DigestSize]uints.U8
	copy(pk[:], pkUints8)

	// Step 11: Return the populated circuit
	return &AssertCnf{
		ProtectedHeaderB64:      p,
		ProtectedHeaderSize:     len(w.ProtectedHeader),
		CnfClaimB64:             c,
		CnfClaimSize:            len(cnfAlignedB64),
		CnfClaimPosition:        cnfB64Index,
		PubKeyDigestHexPosition: pubKeyDigestHexPosition,
		PublicKeyDigest:         pk,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	digestBytes, err := hex.DecodeString(w.PublicKeyDigestHex)
	if err != nil {
		return nil, fmt.Errorf("invalid public key digest: %w", err)
	}
	if len(digestBytes) != SHA256DigestSize {
		return nil, fmt.Errorf("public key digest must be %d bytes", SHA256DigestSize)
	}

	d, err := zkcore.BytesToU8ArrayWithPadding(digestBytes, SHA256DigestSize)
	if err != nil {
		return nil, fmt.Errorf("failed to map to U8: %v", err)
	}

	var pk [SHA256DigestSize]uints.U8
	copy(pk[:], d)

	// Initialize empty arrays for private inputs
	emptyProtected, _ := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxProtectedHeaderSize)
	emptyCnf, _ := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxCnfClaimSize)

	var protectedHeader [MaxProtectedHeaderSize]uints.U8
	var cnfClaim [MaxCnfClaimSize]uints.U8
	copy(protectedHeader[:], emptyProtected)
	copy(cnfClaim[:], emptyCnf)

	// Note: all witness values must be initialised
	return &AssertCnf{
		ProtectedHeaderB64:      protectedHeader,
		ProtectedHeaderSize:     0,
		CnfClaimB64:             cnfClaim,
		CnfClaimSize:            0,
		CnfClaimPosition:        0,
		PubKeyDigestHexPosition: 0,
		PublicKeyDigest:         pk,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs
// These are the secret values the prover knows but doesn't want to reveal
type PrivateInput struct {
	// ProtectedHeader is the complete base64url-encoded JWS protected
	// header
	// Example: "eyJhbGciOiJFUzI1NiIsImNuZiI6eyJ4NXQjUzI1NiI6ImExYjJjM2Q0In19"
	ProtectedHeader string `json:"protected" description:"BASE64URL encoded JWS protected header"`

	// CnfClaim is the cnf claim as a JSON object (NOT encoded)
	// Example: {"cnf":{"kid":"a1b2c3d4e5f6789012345678901234567890123456789012345678901234"}}
	// The parser will encode this to base64url and find its position in the
	// header Per RFC 7800, the cnf claim confirms possession of a
	// proof-of-possession key
	CnfClaim map[string]any `json:"cnf" description:"cnf claim as JSON object (will be encoded by parser)"`
}

// PublicInput defines the JSON structure for public inputs
// This is what the verifier needs to know - what public key digest we're checking for
type PublicInput struct {
	// PublicKeyDigestHex is the SHA-256 digest of the public key in hexadecimal format
	// Example: "a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
	// 64 hex characters representing 32 bytes
	PublicKeyDigestHex string `json:"publicKeyDigestHex" description:"Hex-encoded SHA-256 digest of the public key (64 hex chars)"`
}

// Constraints defines the circuit constraints
// cnf size constraint applies to the marshalled cnf JSON object
var Constraints = map[string]circuits.Constraints{
	"protected": {
		Max: MaxProtectedHeaderSize,
	},
	"cnf": {
		Max: MaxCnfClaimSize,
	},
	"publicKeyDigestHex": {
		Max: MaxCnfClaimSize,
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a ZK proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (public key digest)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (header and cnf claim)"`
}

// ProveResponse defines the response body containing the generated proof
type ProveResponse struct {
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// ========================================================================
// VERIFY ENDPOINT - POST /verify
// ========================================================================

// VerifyRequest defines the request body for verifying a ZK proof
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

// API implements the InputParser interface for the cnf comparison circuit
type API struct{}

// Parse parses the HTTP API inputs to ZK Circuit inputs
func (api *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse JSON into Go structs
	var publicInput PublicInput
	var privateInput PrivateInput

	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	if privateInputJSON == nil {
		w := WitnessInput{
			PublicKeyDigestHex: publicInput.PublicKeyDigestHex,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	w := WitnessInput{
		ProtectedHeader:    privateInput.ProtectedHeader,
		CnfClaim:           privateInput.CnfClaim,
		PublicKeyDigestHex: publicInput.PublicKeyDigestHex,
	}

	return w.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit
var Info = &circuits.CircuitInfo{
	// Circuit version
	Version: 1,

	// Circuit template with appropriately sized arrays
	Circuit: &AssertCnf{
		ProtectedHeaderB64:      [MaxProtectedHeaderSize]uints.U8{}, // Large enough for typical JWT headers
		CnfClaimB64:             [MaxCnfClaimSize]uints.U8{},        // cnf claim is smaller than full header
		CnfClaimPosition:        0,
		PubKeyDigestHexPosition: 0,
		PublicKeyDigest:         [SHA256DigestSize]uints.U8{}, // SHA-256 is always 32 bytes
	},

	Name: "assert-cnf",

	Description: "Proves that a JWS protected header contains a cnf (confirmation) claim per RFC 7800 with a specific public key digest, without revealing the full header contents. Verifies: (1) cnf is substring of header, (2) base64url decoding, (3) hex decoding of digest, (4) digest equality.",

	// LongDescription: DescriptionLong,
	LongDescription: DescriptionLong,

	InputParser: &API{},

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
