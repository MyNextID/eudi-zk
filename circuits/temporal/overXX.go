// Package overxx implements temporal constraint ZK circuits for age verification
package overxx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	MaxPayloadBytes = 3072 // Maximum size for base64url encoded payload
	MaxClaimBytes   = 32   // Maximum size for claim name (e.g., "birthdate", "date_of_birth")
	MaxDateB64Bytes = 128  // Maximum size for base64url encoded date claim
	DateSize        = 10   // Size of date string (YYYY-MM-DD format: 10 characters)
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
OverXX defines a zero-knowledge circuit that proves a person meets an age 
threshold (e.g., over 18) based on their birthdate in a credential, without 
revealing the actual birthdate or the full credential payload.

Use case: Prove age eligibility without revealing your exact date of birth or 
other personal information contained in the credential. This is useful for 
age-restricted services, legal compliance, and privacy-preserving identity 
verification.

The circuit performs the following operations:

1. Verifies that a base64url-encoded date claim is embedded within the 
   base64url-encoded credential payload at a specific position (using 
   padding-aware subset verification)
2. Verifies that the specified claim name (e.g., "birthdate", "date_of_birth") 
   appears within the date claim at a specific position, ensuring the correct 
   field is being validated
3. Decodes the base64url-encoded date claim to extract the JSON data
4. Extracts the actual date string (YYYY-MM-DD format) from within the decoded 
   JSON at a specific position
5. Performs lexicographical comparison to verify the date is before the 
   threshold date (proving the person meets the age requirement)

The payload, date claim, and all positions remain secret, while the threshold 
date and claim name are public. This allows the verifier to specify which date 
field to check (e.g., "birthdate" vs "date_of_birth") while maintaining privacy 
of the actual date and credential contents.
`

// Circuit verifies age eligibility based on birthdate comparison
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// Payload is the base64url-encoded credential payload containing the date claim
	// This remains secret and is not revealed in the proof
	Payload     [MaxPayloadBytes]uints.U8 `gnark:",secret"`
	PayloadSize frontend.Variable         `gnark:",secret"`

	// DateB64 is the base64url-encoded date claim extracted from the payload
	// Example: "ImJpcnRoZGF0ZSI6IjE5OTAtMDEtMDEi" (base64url of {"birthdate":"1990-01-01"})
	// This is secret to hide the actual date
	DateB64     [MaxDateB64Bytes]uints.U8 `gnark:",secret"`
	DateSize    frontend.Variable         `gnark:",secret"`
	DateB64Size frontend.Variable         `gnark:",secret"`

	// DateB64Position is the start position of DateB64 within the Payload
	// This is secret to hide where in the credential the date appears
	DateB64Position frontend.Variable `gnark:",secret"`

	// ClaimPosition is the position where the claim name appears within the decoded DateB64
	// This is secret to maintain privacy of the credential structure
	ClaimPosition frontend.Variable `gnark:",secret"`

	// DatePosition is the position of the actual date string (YYYY-MM-DD)
	// within the decoded DateB64 JSON
	// This is secret as it relates to the structure of the credential
	DatePosition frontend.Variable `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// ThresholdDate is the age threshold date (YYYY-MM-DD format)
	// Anyone born before this date meets the age requirement
	// Example: "2006-01-01" means anyone born before 2006-01-01 is over 18
	ThresholdDate [DateSize]uints.U8 `gnark:",public"`

	// Claim is the name of the date field to verify (e.g., "birthdate", "date_of_birth")
	// This allows the verifier to specify which date field should be validated
	// Can be extended to attest credential type (e.g., "vct" in SD-JWT VC, "namespace" in ISO, "type" in W3C)
	Claim     [MaxClaimBytes]uints.U8 `gnark:",public"`
	ClaimSize frontend.Variable       `gnark:",public"`
}

// Define defines the age verification ZK circuit logic
//
// In this circuit, we prove: "I know a Payload containing a date claim such that:
//  1. DateB64 is a substring of Payload at position DateB64Position
//  2. Claim is a substring of the decoded DateB64 at position ClaimPosition (verifying correct field)
//  3. When DateB64 is base64url-decoded, it contains a date at DatePosition
//  4. That date is lexicographically less than ThresholdDate (proving age eligibility)"
//
// Inputs except ThresholdDate and Claim are secret, providing strong privacy.
func (c *Circuit) Define(api frontend.API) error {
	// Step 1: Verify that DateB64 is embedded in the Payload at the specified position
	// Uses padding-aware comparison to handle variable-length inputs
	// This proves the date claim is genuinely part of the credential
	zkcore.AssertIsSubsetWithPadding(api, c.Payload[:], c.PayloadSize, c.DateB64[:], c.DateB64Size, c.DateB64Position)

	// Step 2: Decode the base64url-encoded date claim
	// This extracts the JSON containing the date field
	dateJSON, err := zkcore.DecodeBase64Url(api, c.DateB64[:])
	if err != nil {
		return fmt.Errorf("failed to decode DateB64: %w", err)
	}

	// Step 3: Verify that the Claim name is embedded in the decoded DateB64 at the specified position
	// This ensures we're validating the correct field (e.g., "birthdate" not "issue_date")
	// The verifier specifies which claim to check, and we prove it exists in our date claim
	zkcore.AssertIsSubsetWithPadding(api, dateJSON, c.DateSize, c.Claim[:], c.ClaimSize, c.ClaimPosition)

	// Step 4: Extract the actual date string (YYYY-MM-DD) from the decoded JSON
	// The date is at a specific position within the JSON (e.g., after "birthdate":")
	dateOfBirth := zkcore.GetSubset(api, dateJSON, c.DatePosition, DateSize)

	// Step 5: Compare the date with the threshold date
	// IsSmaller returns 1 if dateOfBirth < ThresholdDate, 0 otherwise
	// Lexicographical comparison: "1990-01-01" < "2006-01-01" returns 1
	isEligible, err := zkcore.IsSmaller(api, dateOfBirth, c.ThresholdDate[:])
	if err != nil {
		return fmt.Errorf("failed to compare dates: %w", err)
	}

	// Step 6: Assert that the person meets the age requirement
	// If date < threshold, they are old enough
	api.AssertIsEqual(isEligible, 1)

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	Payload         string // Base64url-encoded credential payload
	DateB64         string // Base64url-encoded date claim
	DateB64Position int    // Position of DateB64 in Payload
	DatePosition    int    // Position of date string within decoded DateB64
	ClaimPosition   int    // Position of claim name within decoded DateB64

	// Public inputs
	ThresholdDate string // Age threshold date (YYYY-MM-DD)
	Claim         string // Claim name to verify (e.g., "birthdate", "date_of_birth")
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate payload
	if len(w.Payload) > MaxPayloadBytes {
		return fmt.Errorf("payload exceeds max size: got %d bytes, max %d",
			len(w.Payload), MaxPayloadBytes)
	}
	if len(w.Payload) == 0 {
		return fmt.Errorf("payload cannot be empty")
	}

	// Validate DateB64
	if len(w.DateB64) > MaxDateB64Bytes {
		return fmt.Errorf("DateB64 exceeds max size: got %d bytes, max %d",
			len(w.DateB64), MaxDateB64Bytes)
	}
	if len(w.DateB64) == 0 {
		return fmt.Errorf("DateB64 cannot be empty")
	}

	// Validate Claim
	if len(w.Claim) > MaxClaimBytes {
		return fmt.Errorf("claim exceeds max size: got %d bytes, max %d",
			len(w.Claim), MaxClaimBytes)
	}
	if len(w.Claim) == 0 {
		return fmt.Errorf("claim cannot be empty")
	}

	// Validate DateB64Position
	if w.DateB64Position < 0 {
		return fmt.Errorf("DateB64Position cannot be negative: %d", w.DateB64Position)
	}
	if w.DateB64Position > len(w.Payload)-len(w.DateB64) {
		return fmt.Errorf("DateB64Position out of range: %d (payload length: %d, DateB64 length: %d)",
			w.DateB64Position, len(w.Payload), len(w.DateB64))
	}

	// Verify DateB64 is actually at the claimed position in payload
	payloadSubstring := w.Payload[w.DateB64Position : w.DateB64Position+len(w.DateB64)]
	if payloadSubstring != w.DateB64 {
		return fmt.Errorf("DateB64 not found at claimed position %d in payload", w.DateB64Position)
	}

	// Decode DateB64 to verify it contains valid JSON
	dateJSON, err := base64.RawURLEncoding.DecodeString(w.DateB64)
	if err != nil {
		return fmt.Errorf("failed to decode DateB64: %w", err)
	}

	// Validate ClaimPosition (against decoded DateB64, not the base64 string)
	if w.ClaimPosition < 0 {
		return fmt.Errorf("ClaimPosition cannot be negative: %d", w.ClaimPosition)
	}
	if w.ClaimPosition > len(dateJSON)-len(w.Claim) {
		return fmt.Errorf("ClaimPosition out of range: %d (decoded DateB64 length: %d, Claim length: %d)",
			w.ClaimPosition, len(dateJSON), len(w.Claim))
	}

	// Verify Claim is actually at the claimed position in decoded DateB64
	dateJSONSubstring := string(dateJSON[w.ClaimPosition : w.ClaimPosition+len(w.Claim)])
	if dateJSONSubstring != w.Claim {
		return fmt.Errorf("claim %q not found at claimed position %d in decoded DateB64", w.Claim, w.ClaimPosition)
	}

	// Validate ThresholdDate format (YYYY-MM-DD)
	if len(w.ThresholdDate) != DateSize {
		return fmt.Errorf("ThresholdDate must be %d bytes (YYYY-MM-DD), got %d",
			DateSize, len(w.ThresholdDate))
	}
	if _, err := time.Parse("2006-01-02", w.ThresholdDate); err != nil {
		return fmt.Errorf("ThresholdDate is not a valid date (YYYY-MM-DD): %w", err)
	}

	// Validate DatePosition
	if w.DatePosition < 0 {
		return fmt.Errorf("DatePosition cannot be negative: %d", w.DatePosition)
	}
	if w.DatePosition+DateSize > len(dateJSON) {
		return fmt.Errorf("DatePosition out of range: %d (decoded DateB64 length: %d)",
			w.DatePosition, len(dateJSON))
	}

	// Extract and validate the date string
	dateStr := string(dateJSON[w.DatePosition : w.DatePosition+DateSize])
	if _, err := time.Parse("2006-01-02", dateStr); err != nil {
		return fmt.Errorf("date at DatePosition is not valid (YYYY-MM-DD): %s, error: %w",
			dateStr, err)
	}

	// Verify age logic: dateStr < ThresholdDate means age requirement is met
	if dateStr >= w.ThresholdDate {
		return fmt.Errorf("age verification would fail: date %s is not before threshold %s",
			dateStr, w.ThresholdDate)
	}

	return nil
}

// CreateWitness creates a new witness for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Convert payload to bytes and pad
	payloadBytes := []byte(w.Payload)
	payloadU8, err := zkcore.BytesToU8ArrayWithPadding(payloadBytes, MaxPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert payload: %w", err)
	}

	// Convert DateB64 to bytes and pad
	dateB64Bytes := []byte(w.DateB64)
	dateB64U8, err := zkcore.BytesToU8ArrayWithPadding(dateB64Bytes, MaxDateB64Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DateB64: %w", err)
	}
	dateBuf, err := base64.RawURLEncoding.DecodeString(w.DateB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DateB64: %w", err)
	}

	// Convert Claim to bytes and pad
	claimBytes := []byte(w.Claim)
	claimU8, err := zkcore.BytesToU8ArrayWithPadding(claimBytes, MaxClaimBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Claim: %w", err)
	}

	// Convert ThresholdDate to U8 array
	thresholdU8 := zkcore.StringToU8Array(w.ThresholdDate)

	// Copy to fixed-size arrays
	var payloadArray [MaxPayloadBytes]uints.U8
	var dateB64Array [MaxDateB64Bytes]uints.U8
	var claimArray [MaxClaimBytes]uints.U8
	var thresholdArray [DateSize]uints.U8

	copy(payloadArray[:], payloadU8)
	copy(dateB64Array[:], dateB64U8)
	copy(claimArray[:], claimU8)
	copy(thresholdArray[:], thresholdU8)

	return &Circuit{
		Payload:         payloadArray,
		PayloadSize:     len(w.Payload),
		DateB64:         dateB64Array,
		DateB64Size:     len(dateB64Bytes),
		DateSize:        len(dateBuf),
		DateB64Position: w.DateB64Position,
		ClaimPosition:   w.ClaimPosition,
		DatePosition:    w.DatePosition,
		Claim:           claimArray,
		ClaimSize:       len(w.Claim),
		ThresholdDate:   thresholdArray,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Convert ThresholdDate to U8 array
	thresholdU8 := zkcore.StringToU8Array(w.ThresholdDate)

	// Convert Claim to bytes and pad
	claimBytes := []byte(w.Claim)
	claimU8, err := zkcore.BytesToU8ArrayWithPadding(claimBytes, MaxClaimBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Claim: %w", err)
	}

	// Create empty secret inputs (not used in verification)
	dateB64U8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxDateB64Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty DateB64: %w", err)
	}

	payloadU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty payload: %w", err)
	}

	// Copy to fixed-size arrays
	var payloadArray [MaxPayloadBytes]uints.U8
	var dateB64Array [MaxDateB64Bytes]uints.U8
	var claimArray [MaxClaimBytes]uints.U8
	var thresholdArray [DateSize]uints.U8

	copy(payloadArray[:], payloadU8)
	copy(dateB64Array[:], dateB64U8)
	copy(claimArray[:], claimU8)
	copy(thresholdArray[:], thresholdU8)

	return &Circuit{
		Payload:         payloadArray,
		PayloadSize:     frontend.Variable(0),
		DateB64:         dateB64Array,
		DateSize:        frontend.Variable(0),
		DateB64Size:     frontend.Variable(0),
		DateB64Position: frontend.Variable(0),
		ClaimPosition:   frontend.Variable(0),
		DatePosition:    frontend.Variable(0),
		Claim:           claimArray,
		ClaimSize:       len(w.Claim),
		ThresholdDate:   thresholdArray,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit
// This data is known only to the prover
type PrivateInput struct {
	// Payload is the base64url-encoded credential payload
	// This contains the date and other personal information
	// Example: A base64url-encoded JSON credential
	Payload string `json:"payload" description:"BASE64URL encoded credential payload (secret)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit
// This data will be visible to anyone verifying the proof
type PublicInput struct {
	// ThresholdDate is the age threshold date (YYYY-MM-DD format)
	// Anyone with a date before this threshold meets the age requirement
	// Example: "2006-01-01" for over 18 verification in 2024
	ThresholdDate string `json:"thresholdDate" description:"Age threshold date (YYYY-MM-DD format, public)"`

	// Claim is the name of the date field to verify
	// This allows the verifier to specify which field should be validated
	// Example: "birthdate", "date_of_birth", "birth_date"
	Claim string `json:"claim" description:"Name of the date field to verify (public)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"payload": {
		Max:         MaxPayloadBytes,
		Description: "Maximum credential payload size (base64url encoded)",
	},
	"date": {
		Max:         MaxDateB64Bytes,
		Description: "Maximum date claim size (base64url encoded)",
	},
	"claim": {
		Max:         MaxClaimBytes,
		Description: "Maximum claim name size",
	},
	"thresholdDate": {
		Max:         DateSize,
		Description: "Date string size (YYYY-MM-DD format: 10 characters)",
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (threshold date and claim name)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (payload, date claim, positions)"`
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
func (a *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse the JSON inputs
	var publicInput PublicInput
	var privateInput PrivateInput

	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// Handle verification case (no private input)
	if privateInputJSON == nil {
		w := WitnessInput{
			ThresholdDate: publicInput.ThresholdDate,
			Claim:         publicInput.Claim,
		}
		return w.CreatePublicWitness()
	}

	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	data, err := ExtractData(privateInput.Payload, publicInput.ThresholdDate, publicInput.Claim)
	if err != nil {
		return nil, fmt.Errorf("failed to extract data: %w", err)
	}

	// Step 2: Create witness with validation
	w := WitnessInput{
		Payload:         privateInput.Payload,
		DateB64:         data.DateB64,
		DateB64Position: data.DateB64Index,
		DatePosition:    data.DateIndex,
		Claim:           data.Claim,
		ClaimPosition:   data.ClaimPosition,
		ThresholdDate:   publicInput.ThresholdDate,
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
	Name: "over18",

	// Description explains what this circuit proves
	Description: "Proves a person meets an age threshold (e.g., over 18) based on a date in a credential, without revealing the date, credential contents, or positions. The verifier can specify which date field to validate (e.g., 'birthdate' vs 'date_of_birth').",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &Circuit{
		Payload:         [MaxPayloadBytes]uints.U8{},
		DateB64:         [MaxDateB64Bytes]uints.U8{},
		Claim:           [MaxClaimBytes]uints.U8{},
		ThresholdDate:   [DateSize]uints.U8{},
		PayloadSize:     0,
		DateB64Size:     0,
		DateB64Position: 0,
		ClaimPosition:   0,
		DatePosition:    0,
		ClaimSize:       0,
		DateSize:        0,
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

// ========================================================================
// HELPER FUNCTIONS
// ========================================================================

// ExtractedData holds the parsed data from the payload
type ExtractedData struct {
	Payload       string
	DateB64       string
	DateB64Index  int
	DateIndex     int
	ThresholdDate string
	Claim         string
	ClaimSize     int
	ClaimPosition int
}

// ExtractData extracts the relevant date information from the payload
func ExtractData(payloadB64 string, thresholdDate string, claim string) (*ExtractedData, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the payload: %w", err)
	}

	// Parse the payload as JSON to find the claim
	var payloadMap map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Verify the claim exists in the payload
	claimValue, exists := payloadMap[claim]
	if !exists {
		return nil, fmt.Errorf("claim %q not found in payload", claim)
	}

	// Find the position of the claim in the JSON
	dateIndexStart, dateIndexEnd, err := GetClaimRange(payloadMap, payloadBytes, claim)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim range: %w", err)
	}
	dateB64 := GetClaimB64(payloadBytes, dateIndexStart, dateIndexEnd)

	// Find where the base64-encoded claim appears in the base64-encoded payload
	b64Index := strings.Index(payloadB64, dateB64)
	if b64Index == -1 {
		return nil, fmt.Errorf("failed to find base64-encoded claim in payload")
	}

	// Decode the claim to find the date position
	claimBytes, err := base64.RawURLEncoding.DecodeString(dateB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claim: %w", err)
	}

	// Convert claim value to string
	claimValueStr, ok := claimValue.(string)
	if !ok {
		return nil, fmt.Errorf("claim value is not a string: %T", claimValue)
	}

	// Find the date string position within the decoded claim
	dateIndex := strings.Index(string(claimBytes), claimValueStr)
	if dateIndex == -1 {
		return nil, fmt.Errorf("failed to find date value in decoded claim")
	}

	// Find the claim name position within the decoded claim
	claimStart := strings.Index(string(claimBytes), claim)
	if claimStart == -1 {
		return nil, fmt.Errorf("failed to find claim name in decoded claim")
	}

	return &ExtractedData{
		Payload:       payloadB64,
		DateB64:       dateB64,
		DateB64Index:  b64Index,
		DateIndex:     dateIndex,
		ThresholdDate: thresholdDate,
		Claim:         claim,
		ClaimPosition: claimStart,
		ClaimSize:     len(claim),
	}, nil
}

// GetClaimRange finds the start and end positions of a claim in the JSON bytes,
// aligned to base64 encoding boundaries
func GetClaimRange(obj map[string]any, objJSON []byte, claim string) (start, end int, err error) {
	element := map[string]any{
		claim: obj[claim],
	}
	elementBytes, err := json.Marshal(element)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to marshal claim: %w", err)
	}
	elementString := string(elementBytes)
	elementString = strings.TrimPrefix(elementString, "{")
	elementString = strings.TrimSuffix(elementString, "}")

	// Find where the claim appears
	indexStart := strings.Index(string(objJSON), elementString)
	if indexStart == -1 {
		return 0, 0, fmt.Errorf("element not found in JSON")
	}
	// Length of the claim variable
	indexEnd := indexStart + len(elementString)

	start, end = zkcore.B64Align(indexStart, indexEnd)
	return start, end, nil
}

// GetClaimB64 extracts and base64url-encodes a substring from JSON bytes
func GetClaimB64(objJSON []byte, indexStart, indexEnd int) string {
	data := objJSON[indexStart:indexEnd]
	return base64.RawURLEncoding.EncodeToString(data)
}
