package ccb

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
// CIRCUIT DEFINITION
// ========================================================================

// CompareCnfCircuit proves that a JWS protected header contains a specific CNF
// claim with a public key digest that matches a given value, WITHOUT revealing
// the full header.
//
// Use case: Prove that a JWT contains a specific public key binding (CNF claim)
// without revealing the entire JWT header or its position within the header.
//
// CNF (Confirmation) Claim: RFC 7800 - Proof-of-Possession Key Semantics for
// JSON Web Tokens (JWTs) Example CNF in JWT header:
// {"cnf":{"x5t#S256":"a1b2c3d4..."}}
//
// The circuit performs these verification steps:
// 1. Verify that the base64url-encoded CNF is a substring of the
// base64url-encoded header
// 2. Decode the CNF from base64url to get the JSON structure
// 3. Extract the hex-encoded public key digest from the decoded CNF
// 4. Decode the hex string to get the raw digest bytes
// 5. Compare the extracted digest with the provided public digest
type CompareCnfCircuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// ProtectedHeaderB64 is the base64url-encoded JWS protected header
	// Example: "eyJhbGciOiJFUzI1NiIsImNuZiI6eyJ4NXQjUzI1NiI6IjEyMzQifX0"
	// This remains secret - we don't reveal the full header contents
	ProtectedHeaderB64 []uints.U8 `gnark:",secret"`

	// CnfClaimB64 is the base64url-encoded substring containing the CNF claim
	// Example: "ImNuZiI6eyJ4NXQjUzI1NiI6IjEyMzQifQ" (part of the header)
	// This is extracted from the header and proves the CNF exists at the claimed position
	CnfClaimB64 []uints.U8 `gnark:",secret"`

	// CnfClaimPosition is the byte position where CnfClaimB64 starts within ProtectedHeaderB64
	// This proves we're not fabricating the CNF - it's actually in the header at this position
	CnfClaimPosition frontend.Variable `gnark:",secret"`

	// PubKeyDigestHexPosition is the byte position of the hex-encoded digest within the decoded CNF
	// After base64url decoding the CNF, this points to where the public key digest starts
	// Example: in '{"cnf":{"x5t#S256":"a1b2c3d4..."}}', points to the start of "a1b2c3d4..."
	PubKeyDigestHexPosition frontend.Variable `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// PublicKeyDigest is the SHA-256 digest of the public key we're checking for
	// This is publicly known - we prove the header contains a CNF with THIS specific digest
	// 32 bytes for SHA-256 hash
	PublicKeyDigest []uints.U8 `gnark:",public"`
}

// Define implements the circuit logic that proves CNF claim validity This
// creates the constraint system that will be converted into a zero-knowledge
// proof
//
// What we prove: "I know a JWS header that contains a CNF claim at a specific
// position, and when decoded, that CNF contains a public key digest matching
// the public input"
func (c *CompareCnfCircuit) Define(api frontend.API) error {
	// Step 1: Verify that CnfClaimB64 is actually contained within ProtectedHeaderB64
	// This proves we're not making up a fake CNF - it must exist in the real header
	// IsSubset checks: ProtectedHeaderB64[CnfClaimPosition:CnfClaimPosition+len(CnfClaimB64)] == CnfClaimB64
	err := zkcore.IsSubset(api, c.ProtectedHeaderB64, c.CnfClaimB64, c.CnfClaimPosition)
	if err != nil {
		return err
	}

	// Step 2: Decode the base64url-encoded CNF claim to get the raw JSON bytes
	// Example: "ImNuZiI6eyJ4NXQjUzI1NiI6IjEyMzQifQ" → '"cnf":{"x5t#S256":"1234"}'
	// This creates constraints that verify correct base64url decoding
	decodedCnfClaim, err := zkcore.DecodeBase64Url(api, c.CnfClaimB64)
	if err != nil {
		return err
	}

	// Step 3: Extract the hex-encoded public key digest from the decoded CNF
	// The digest is a SHA-256 hash hex-encoded, so it's 64 hex characters (32 bytes * 2)
	// Example: "a1b2c3d4e5f6..." (64 characters representing 32 bytes)
	const Sha256HexSize = 64 // 32 bytes * 2 hex chars per byte
	pubKeyDigestHex := zkcore.GetSubset(api, decodedCnfClaim, c.PubKeyDigestHexPosition, Sha256HexSize)

	// Step 4: Decode the hex string to get the raw digest bytes
	// Example: "a1b2" → [0xa1, 0xb2]
	// This creates constraints that verify correct hex decoding
	extractedDigestBytes, err := zkcore.DecodeHex(api, pubKeyDigestHex)
	if err != nil {
		return err
	}

	// Step 5: Verify that the extracted digest matches the public digest
	// This is the final proof: the digest we extracted from the header equals the public input
	// If they don't match, the proof generation will fail
	zkcore.AssertIsEqualBytes(api, extractedDigestBytes, c.PublicKeyDigest)

	return nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// CompareCnfPublicInput defines the JSON structure for public inputs
// This is what the verifier needs to know - what public key digest we're checking for
type CompareCnfPublicInput struct {
	// PublicKeyDigestHex is the SHA-256 digest of the public key in hexadecimal format
	// Example: "a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
	// 64 hex characters representing 32 bytes
	PublicKeyDigestHex string `json:"public_key_digest_hex" description:"Hex-encoded SHA-256 digest of the public key (64 hex chars)"`
}

// CompareCnfPrivateInput defines the JSON structure for private inputs
// These are the secret values the prover knows but doesn't want to reveal
type CompareCnfPrivateInput struct {
	// ProtectedHeaderB64Url is the complete base64url-encoded JWS protected
	// header
	// Example: "eyJhbGciOiJFUzI1NiIsImNuZiI6eyJ4NXQjUzI1NiI6ImExYjJjM2Q0In19"
	ProtectedHeaderB64Url string `json:"protected" description:"BASE64URL encoded JWS protected header"`

	// CnfClaimJSON is the CNF claim as a JSON object (NOT encoded)
	// Example: {"cnf":{"x5t#S256":"a1b2c3d4e5f6789012345678901234567890123456789012345678901234"}}
	// The parser will encode this to base64url and find its position in the
	// header Per RFC 7800, the CNF claim confirms possession of a
	// proof-of-possession key
	CnfClaimJSON map[string]interface{} `json:"cnf" description:"CNF claim as JSON object (will be encoded by parser)"`
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// CompareCnfProveRequest defines the request body for generating a ZK proof
type CompareCnfProveRequest struct {
	Public  CompareCnfPublicInput  `json:"public" description:"Public ZK circuit inputs (public key digest)"`
	Private CompareCnfPrivateInput `json:"private" description:"Private ZK circuit inputs (header and CNF claim)"`
}

// CompareCnfProveResponse defines the response body containing the generated proof
type CompareCnfProveResponse struct {
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof"`
}

// ========================================================================
// VERIFY ENDPOINT - POST /verify
// ========================================================================

// CompareCnfVerifyRequest defines the request body for verifying a ZK proof
type CompareCnfVerifyRequest struct {
	Public CompareCnfPublicInput `json:"public" description:"Public ZK circuit inputs (must match prove request)"`
	Proof  string                `json:"proof" description:"BASE64URL encoded ZK proof to verify"`
}

// CompareCnfVerifyResponse defines the response body from proof verification
type CompareCnfVerifyResponse struct {
	// Success indicates if the verification process completed (not if proof is valid)
	Success string `json:"success"`

	// Valid indicates if the proof is mathematically valid
	// true = the proof is correct, false = the proof is invalid or incorrect
	Valid bool `json:"valid"`

	// Message contains optional error or status information
	Message *string `json:"message,omitempty"`
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// CompareCnfInfo contains all metadata needed to register this circuit
var CompareCnfInfo = &circuits.CircuitInfo{
	// Circuit template with appropriately sized arrays
	Circuit: &CompareCnfCircuit{
		ProtectedHeaderB64:      make([]uints.U8, circuits.ByteSize256), // Large enough for typical JWT headers
		CnfClaimB64:             make([]uints.U8, circuits.ByteSize128), // CNF claim is smaller than full header
		CnfClaimPosition:        0,
		PubKeyDigestHexPosition: 0,
		PublicKeyDigest:         make([]uints.U8, circuits.ByteSize32), // SHA-256 is always 32 bytes
	},

	Name: "compare-cnf",

	Description: "Proves that a JWS protected header contains a CNF (confirmation) claim per RFC 7800 with a specific public key digest, without revealing the full header contents. Verifies: (1) CNF is substring of header, (2) base64url decoding, (3) hex decoding of digest, (4) digest equality.",

	Version: 1,

	InputParser: &CompareCnfAPI{},

	EndpointInfo: &circuits.EndpointInfo{
		Prove: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CompareCnfProveRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CompareCnfProveResponse{}, nil),
		},
		Verify: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CompareCnfVerifyRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CompareCnfVerifyResponse{}, nil),
		},
	},
}

// ========================================================================
// INPUT PARSER - Converts API JSON to circuit format
// ========================================================================

// CompareCnfAPI implements the InputParser interface for the CNF comparison circuit
type CompareCnfAPI struct{}

// Parse parses the HTTP API inputs to ZK Circuit inputs
func (api *CompareCnfAPI) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse JSON into Go structs
	var publicInput CompareCnfPublicInput
	var privateInput CompareCnfPrivateInput

	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 2: Process public input - decode hex to bytes
	publicKeyDigestBytes, err := hex.DecodeString(publicInput.PublicKeyDigestHex)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode public key digest: %w", err)
	}

	if len(publicKeyDigestBytes) != 32 {
		return nil, fmt.Errorf("public key digest must be 32 bytes (SHA-256), got %d bytes", len(publicKeyDigestBytes))
	}

	// Step 3: Encode CNF claim and trim braces to get the field content
	cnfClaimJSONBytes, err := json.Marshal(privateInput.CnfClaimJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CNF claim JSON: %w", err)
	}

	// Remove outer braces: {"cnf":...} becomes "cnf":...
	cnfStr := strings.TrimPrefix(string(cnfClaimJSONBytes), "{")
	cnfStr = strings.TrimSuffix(cnfStr, "}")

	// Step 4: Encode the protected header to find positions
	protectedHeaderJSONBytes, err := json.Marshal(privateInput.ProtectedHeaderB64Url)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protected header JSON: %w", err)
	}

	// Step 5: Find where the cnf field appears in the protected header JSON
	cnfStart := strings.Index(string(protectedHeaderJSONBytes), cnfStr)
	if cnfStart == -1 {
		return nil, fmt.Errorf("CNF field not found in protected header JSON")
	}

	// Step 6: Align to base64 boundaries
	cnfLen := len(cnfStr)
	cnfEnd := cnfStart + cnfLen
	cnfStartAligned, cnfEndAligned := zkcore.B64Align(cnfStart, cnfEnd)

	// Extract the aligned section
	cnfAligned := protectedHeaderJSONBytes[cnfStartAligned:cnfEndAligned]

	// Step 7: Base64url encode both the full header and the aligned CNF section
	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedHeaderJSONBytes)
	cnfAlignedB64 := base64.RawURLEncoding.EncodeToString(cnfAligned)

	// Step 8: Verify the aligned CNF appears in the base64 encoded header
	cnfB64Index := strings.Index(protectedB64, cnfAlignedB64)
	if cnfB64Index == -1 {
		return nil, fmt.Errorf("aligned CNF not found in base64 encoded protected header")
	}

	// Step 9: Find the public key digest hex within the aligned section
	pubKeyDigestHexPosition := strings.Index(string(cnfAligned), publicInput.PublicKeyDigestHex)
	if pubKeyDigestHexPosition == -1 {
		return nil, fmt.Errorf("public key digest hex not found in aligned CNF section")
	}

	// Step 10: Validate the digest matches
	digestHexFromCnf := string(cnfAligned)[pubKeyDigestHexPosition : pubKeyDigestHexPosition+64]
	digestBytesFromCnf, err := hex.DecodeString(digestHexFromCnf)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode digest from CNF: %w", err)
	}

	if !bytes.Equal(digestBytesFromCnf, publicKeyDigestBytes) {
		return nil, fmt.Errorf("digest mismatch: CNF digest does not match public input")
	}

	// Step 11: Return the populated circuit
	return &CompareCnfCircuit{
		ProtectedHeaderB64:      zkcore.StringToU8Array(protectedB64),
		CnfClaimB64:             zkcore.StringToU8Array(cnfAlignedB64),
		CnfClaimPosition:        cnfB64Index,
		PubKeyDigestHexPosition: pubKeyDigestHexPosition,
		PublicKeyDigest:         zkcore.BytesToU8Array(publicKeyDigestBytes),
	}, nil
}
