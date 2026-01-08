// Package minicrl implements the Mini CRL circuit for proving certificate non-revocation
package minicrl

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
	MaxCRLBytes  = 512 // Maximum size of Mini CRL in DER format
	MaxCertBytes = 512 // Maximum size of Certificate in DER format
	MaxSerialLen = 10  // Maximum certificate serial number length (10 bytes)
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
MiniCRL defines a zero-knowledge circuit that proves a certificate's serial
number is NOT present in a Certificate Revocation List (CRL) without revealing
the certificate revocation identifier or the CRL.

The circuit verifies that the certificate serial number does not fall within the
range specified by two consecutive CRL entries, proving the certificate is valid
and not revoked.

Use case: Prove your certificate is not revoked without revealing your
certificate details or the complete CRL contents.
`

// Circuit defines a ZK circuit that verifies certificate non-revocation
// The circuit focuses on two main operations:
//
// - Extract the certificate serial number from the DER-encoded certificate
// - Prove that the serial number is NOT in the range between two CRL entries
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// CertBytes is the DER-encoded X.509 certificate (secret)
	// We extract the serial number from this without revealing the full cert
	CertBytes [MaxCertBytes]uints.U8 `gnark:",secret"`

	// ===== PRIVATE INPUTS (Known to Prover) =====

	// CRLBytes is the Mini CRL in DER format
	// Contains exactly two serial numbers
	CRLBytes [MaxCRLBytes]uints.U8 `gnark:",secret"`
}

// Define implements the gnark Circuit interface
// This is the core of the zero-knowledge proof
//
// We prove: "I know a certificate whose serial number is NOT in the provided CRL"
func (c *Circuit) Define(api frontend.API) error {
	return VerifySerialNotRevoked(api, c.CertBytes[:], c.CRLBytes[:], MaxSerialLen)
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// Private inputs
	CRLBytes  string // Base64url encoded DER-format Mini CRL
	CertBytes string // Base64url encoded DER-format Certificate

}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate CRL bytes
	crlBuf, err := base64.RawURLEncoding.DecodeString(w.CRLBytes)
	if err != nil {
		return fmt.Errorf("failed to decode CRL input: %v", err)
	}
	if len(crlBuf) > MaxCRLBytes {
		return fmt.Errorf("CRL input exceeds maximum size %d, got %d", MaxCRLBytes, len(crlBuf))
	}

	// Validate certificate bytes
	certBuf, err := base64.RawURLEncoding.DecodeString(w.CertBytes)
	if err != nil {
		return fmt.Errorf("failed to decode certificate input: %v", err)
	}
	if len(certBuf) > MaxCertBytes {
		return fmt.Errorf("certificate input exceeds maximum size %d, got %d", MaxCertBytes, len(certBuf))
	}

	return nil
}

// CreateWitness creates a new witness with all inputs
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Decode CRL bytes
	crlBuf, err := base64.RawURLEncoding.DecodeString(w.CRLBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CRL input: %v", err)
	}
	crlU8, err := zkcore.BytesToU8ArrayWithPadding(crlBuf, MaxCRLBytes)
	if err != nil {
		return nil, err
	}

	// Decode certificate bytes
	certBuf, err := base64.RawURLEncoding.DecodeString(w.CertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate input: %v", err)
	}
	certU8, err := zkcore.BytesToU8ArrayWithPadding(certBuf, MaxCertBytes)
	if err != nil {
		return nil, err
	}

	// Copy to fixed-size arrays
	var crl [MaxCRLBytes]uints.U8
	var cert [MaxCertBytes]uints.U8
	copy(crl[:], crlU8)
	copy(cert[:], certU8)

	return &Circuit{
		CRLBytes:  crl,
		CertBytes: cert,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {

	// Create empty arrays for private/secret inputs
	crlU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxCRLBytes)
	if err != nil {
		return nil, err
	}
	certU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxCertBytes)
	if err != nil {
		return nil, err
	}

	var crl [MaxCRLBytes]uints.U8
	var cert [MaxCertBytes]uints.U8
	copy(crl[:], crlU8)
	copy(cert[:], certU8)

	return &Circuit{
		CRLBytes:  crl,
		CertBytes: cert,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs sent via API
type PrivateInput struct {
	// CRLBytes contains base64url encoded DER-format Mini CRL
	CRLBytes string `json:"crl_bytes" description:"BASE64URL encoded Mini CRL in DER format"`

	// CertBytes contains base64url encoded DER-format certificate
	CertBytes string `json:"cert_bytes" description:"BASE64URL encoded X.509 certificate in DER format"`
}

// PublicInput defines the JSON structure for public inputs sent via API
type PublicInput struct {
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"crl_bytes": {
		Max: MaxCRLBytes,
	},
	"cert_bytes": {
		Max: MaxCertBytes,
	},
	"serial_number": {
		Max: MaxSerialLen,
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (CRL hash)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (CRL and certificate)"`
}

// ProveResponse defines the response body containing the generated proof
type ProveResponse struct {
	// Proof is the base64url encoded zero-knowledge proof
	Proof string `json:"proof" description:"BASE64URL encoded ZK proof of non-revocation"`
}

// ========================================================================
// VERIFY ENDPOINT - POST /verify
// ========================================================================

// VerifyRequest defines the request body for verifying a zero-knowledge proof
type VerifyRequest struct {
	Public PublicInput `json:"public" description:"Public ZK circuit inputs (CRL hash)"`
	Proof  string      `json:"proof" description:"BASE64URL encoded ZK proof to verify"`
}

// VerifyResponse defines the response body from proof verification
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

// Parse converts JSON-encoded API inputs into a populated circuit instance
func (api *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse public input JSON
	var publicInput PublicInput
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// Step 2: Handle public-only witness (for verification)
	if privateInputJSON == nil {
		w := WitnessInput{}
		return w.CreatePublicWitness()
	}

	// Step 3: Parse private input JSON
	var privateInput PrivateInput
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 4: Create full witness
	w := WitnessInput(privateInput)

	// Validate inputs
	if err := w.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return w.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit with the framework
var Info = &circuits.CircuitInfo{
	// Name is the circuit identifier used in API routes
	Name: "mini-crl",

	// Description explains what this circuit proves
	Description: "Proves that a certificate's serial number is NOT present in a Certificate Revocation List (CRL) without revealing the certificate details. Verifies non-revocation status using DER-encoded certificates and Mini CRL format.",

	LongDescription: DescriptionLong,

	// Version enables API versioning
	Version: 1,

	// Circuit is a template instance with properly sized arrays
	Circuit: &Circuit{
		CRLBytes:  [MaxCRLBytes]uints.U8{},
		CertBytes: [MaxCertBytes]uints.U8{},
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
