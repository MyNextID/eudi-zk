// Package verifyjwscert is a ZK circuit that verifies JWS signatures with X.509
// certificate chain validation
package verifyjwscert

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/zkcore"
)

// ========================================================================
// CIRCUIT CONSTANTS
// ========================================================================

// Circuit input sizes
const (
	MaxJWSProtectedBytes = 256 // Maximum size for JWS protected header
	MaxJWSPayloadBytes   = 256 // Maximum size for JWS payload
	MaxCertTBSBytes      = 512 // Maximum size for certificate TBS (To Be Signed) data
	SHA256DigestSize     = 32  // SHA-256 produces 32-byte digests
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
VerifyJWSCert circuit proves that a JWS (JSON Web Signature) is
cryptographically valid and was signed by a certificate issued by a trusted
Qualified Trust Service Provider (QTSP), WITHOUT revealing the signer's identity
or full certificate.

Use case: Prove that a digital signature on a document is valid and comes from 
a QTSP-certified entity, while keeping the actual signer's identity private.

JWS (JSON Web Signature): RFC 7515 - A compact digital signature format
consisting of three base64url-encoded parts: Protected Header, Payload, and
Signature.

X.509 Certificate Chain: RFC 5280 - A hierarchical trust model where a QTSP 
(trusted authority) signs certificates for end entities (signers).

The circuit performs these verification steps:

1. Verify JWS Signature: Prove that the JWS signature is mathematically valid
   for the given protected header and payload using the signer's public key
   
2. Verify Certificate Signature: Prove that the signer's X.509 certificate 
   was validly signed by the QTSP (trusted authority)
   
3. Verify Public Key Binding: Prove that the public key used to verify the 
   JWS signature is the same public key embedded in the X.509 certificate

Zero-Knowledge Properties:
- PRIVATE: JWS protected header, signer's identity, complete X.509 certificate
- PUBLIC: JWS payload (the signed data), QTSP's public key (the trust anchor)
`

// Circuit defines the circuit input parameters
type Circuit struct {
	// ===== SECRET INPUTS (Private Witness) =====

	// JWSProtected is the base64url-encoded JWS protected header
	// Example: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" (contains algorithm, type, etc.)
	// This remains secret - we don't reveal metadata about the signature
	JWSProtected []uints.U8 `gnark:",secret"`

	// ProtectedSize is the actual protected header size without padding
	ProtectedSize frontend.Variable `gnark:",secret"`

	// JWSSigR is the R component of the ECDSA signature on the JWS
	// ECDSA signatures consist of two big integers: (R, S)
	// This proves the JWS was signed by someone with the private key
	JWSSigR emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// JWSSigS is the S component of the ECDSA signature on the JWS
	JWSSigS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// SignerPubKeyX is the X coordinate of the signer's ECDSA public key
	// This is the key that was used to create the JWS signature
	// We keep it private to hide the signer's identity
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// SignerPubKeyY is the Y coordinate of the signer's ECDSA public key
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// CertTBSDER is the DER-encoded TBS (To Be Signed) portion of the X.509
	// certificate
	// The TBS contains all certificate data except the signature itself
	// Example contents: subject name, issuer name, public key, validity period
	CertTBSDER []uints.U8 `gnark:",secret"`

	// CertTBSDERSize is the actual certificate TBS size without padding
	CertTBSDERSize frontend.Variable `gnark:",secret"`

	// CertSigR is the R component of the ECDSA signature on the certificate
	// This signature was created by the QTSP to certify the signer's public key
	CertSigR emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// CertSigS is the S component of the ECDSA signature on the certificate
	CertSigS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// Hash is the SHA-256 digest of the JWS signing input (protected.payload)
	// Pre-computed to save circuit constraints
	Hash [SHA256DigestSize]uints.U8 `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// JWSPayload is the base64url-encoded payload that was signed
	// This is publicly known - we prove the signature is valid for THIS payload
	// Example: "eyJzdWIiOiIxMjM0NTY3ODkwIn0" (contains the actual signed data)
	JWSPayload []uints.U8 `gnark:",public"`

	// PayloadSize is the actual payload size without padding
	PayloadSize frontend.Variable `gnark:",secret"`

	// QTSPPubKeyX is the X coordinate of the QTSP's public key
	// This is the trust anchor - the publicly known key of the trusted authority
	QTSPPubKeyX emulated.Element[Secp256r1Fp] `gnark:",public"`

	// QTSPPubKeyY is the Y coordinate of the QTSP's public key
	QTSPPubKeyY emulated.Element[Secp256r1Fp] `gnark:",public"`
}

// Define implements the circuit logic that proves JWS signature validity with
// certificate chain
// This creates the constraint system that will be converted into a
// zero-knowledge proof
//
// What we prove: "I know a valid JWS signature over a public payload, created
// with a private key whose public key is embedded in an X.509 certificate that
// was validly signed by the known QTSP"
func (c *Circuit) Define(api frontend.API) error {
	// Step 1: Verify the JWS signature is valid
	// This proves: ECDSA_Verify(SignerPubKey, Hash(Protected || "." ||
	// Payload), JWSSig) == true
	if err := c.VerifyJWS(api); err != nil {
		return fmt.Errorf("JWS signature verification failed: %w", err)
	}

	// Step 2: Verify the X.509 certificate signature is valid
	// This proves: ECDSA_Verify(QTSPPubKey, Hash(CertTBS), CertSig) == true
	if err := c.VerifyX509Signature(api); err != nil {
		return fmt.Errorf("X.509 certificate verification failed: %w", err)
	}

	// Step 3: Verify the signer's public key is embedded in the certificate
	// This proves: SignerPubKey is contained within CertTBS
	// This binds the JWS signature to the certificate chain
	if err := c.verifyPubKeyInCertificateSimplified(api); err != nil {
		return fmt.Errorf("public key binding verification failed: %w", err)
	}

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw inputs before conversion to circuit witness
type WitnessInput struct {
	// ===== PRIVATE INPUTS =====

	// JWSProtected is the base64url-encoded protected header string
	JWSProtected string

	// JWSSigR and JWSSigS are the ECDSA signature components for the JWS
	JWSSigR *big.Int
	JWSSigS *big.Int

	// SignerPubKeyX and SignerPubKeyY are the signer's public key coordinates
	SignerPubKeyX *big.Int
	SignerPubKeyY *big.Int

	// CertTBSDER is the base64url-encoded TBS certificate data
	CertTBSDER string

	// CertSigR and CertSigS are the ECDSA signature components for the certificate
	CertSigR *big.Int
	CertSigS *big.Int

	// Hash is the base64url-encoded SHA-256 digest of the JWS signing input
	Hash string

	// ===== PUBLIC INPUTS =====

	// JWSPayload is the base64url-encoded payload string
	JWSPayload string

	// QTSPPubKeyX and QTSPPubKeyY are the QTSP's public key coordinates
	QTSPPubKeyX *big.Int
	QTSPPubKeyY *big.Int
}

// Validate performs input validation
func (w *WitnessInput) Validate() error {
	// Validate private inputs are valid base64url
	if _, err := base64.RawURLEncoding.DecodeString(w.JWSProtected); err != nil {
		return fmt.Errorf("invalid base64url encoding for JWS protected header: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(w.CertTBSDER); err != nil {
		return fmt.Errorf("invalid base64url encoding for certificate TBS: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(w.Hash); err != nil {
		return fmt.Errorf("invalid base64url encoding for hash: %w", err)
	}

	// Validate public inputs
	if _, err := base64.RawURLEncoding.DecodeString(w.JWSPayload); err != nil {
		return fmt.Errorf("invalid base64url encoding for JWS payload: %w", err)
	}

	// Validate signature components are non-nil
	if w.JWSSigR == nil || w.JWSSigS == nil {
		return fmt.Errorf("JWS signature components cannot be nil")
	}
	if w.CertSigR == nil || w.CertSigS == nil {
		return fmt.Errorf("certificate signature components cannot be nil")
	}

	// Validate public key components are non-nil
	if w.SignerPubKeyX == nil || w.SignerPubKeyY == nil {
		return fmt.Errorf("signer public key components cannot be nil")
	}
	if w.QTSPPubKeyX == nil || w.QTSPPubKeyY == nil {
		return fmt.Errorf("QTSP public key components cannot be nil")
	}

	return nil
}

// CreateWitness creates a full witness with both private and public inputs
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	// Step 1: Decode base64url encoded strings to bytes
	jwsProtectedBytes := []byte(w.JWSProtected)
	jwsPayloadBytes := []byte(w.JWSPayload)

	certTBSBytes, err := base64.RawURLEncoding.DecodeString(w.CertTBSDER)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate TBS: %w", err)
	}

	hashBytes, err := base64.RawURLEncoding.DecodeString(w.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Step 2: Convert byte slices to U8 arrays with padding
	jwsProtectedU8, err := zkcore.BytesToU8ArrayWithPadding(jwsProtectedBytes, MaxJWSProtectedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWS protected header to U8 array: %w", err)
	}

	jwsPayloadU8, err := zkcore.BytesToU8ArrayWithPadding(jwsPayloadBytes, MaxJWSPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWS payload to U8 array: %w", err)
	}

	certTBSU8, err := zkcore.BytesToU8ArrayWithPadding(certTBSBytes, MaxCertTBSBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate TBS to U8 array: %w", err)
	}

	// Step 3: Convert hash bytes to fixed-size array
	hashU8 := zkcore.BytesToU8Array(hashBytes)
	var hashArray [SHA256DigestSize]uints.U8
	copy(hashArray[:], hashU8)

	// Step 4: Convert big integers to emulated field elements
	// For JWS signature
	jwsSigR := emulated.ValueOf[Secp256r1Fr](w.JWSSigR)
	jwsSigS := emulated.ValueOf[Secp256r1Fr](w.JWSSigS)

	// For signer's public key
	signerPubKeyX := emulated.ValueOf[Secp256r1Fp](w.SignerPubKeyX)
	signerPubKeyY := emulated.ValueOf[Secp256r1Fp](w.SignerPubKeyY)

	// For certificate signature
	certSigR := emulated.ValueOf[Secp256r1Fr](w.CertSigR)
	certSigS := emulated.ValueOf[Secp256r1Fr](w.CertSigS)

	// For QTSP public key
	qtspPubKeyX := emulated.ValueOf[Secp256r1Fp](w.QTSPPubKeyX)
	qtspPubKeyY := emulated.ValueOf[Secp256r1Fp](w.QTSPPubKeyY)

	// Step 5: Populate and return the circuit struct
	return &Circuit{
		// Private inputs
		JWSProtected:   jwsProtectedU8,
		ProtectedSize:  len(w.JWSProtected),
		JWSSigR:        jwsSigR,
		JWSSigS:        jwsSigS,
		SignerPubKeyX:  signerPubKeyX,
		SignerPubKeyY:  signerPubKeyY,
		CertTBSDER:     certTBSU8,
		CertTBSDERSize: len(certTBSBytes),
		CertSigR:       certSigR,
		CertSigS:       certSigS,
		Hash:           hashArray,

		// Public inputs
		JWSPayload:  jwsPayloadU8,
		PayloadSize: len(w.JWSPayload),
		QTSPPubKeyX: qtspPubKeyX,
		QTSPPubKeyY: qtspPubKeyY,
	}, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	// Step 1: Process public inputs
	jwsPayloadBytes := []byte(w.JWSPayload)
	jwsPayloadU8, err := zkcore.BytesToU8ArrayWithPadding(jwsPayloadBytes, MaxJWSPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWS payload to U8 array: %w", err)
	}

	qtspPubKeyX := emulated.ValueOf[Secp256r1Fp](w.QTSPPubKeyX)
	qtspPubKeyY := emulated.ValueOf[Secp256r1Fp](w.QTSPPubKeyY)

	// Step 2: Create empty/zero values for private inputs
	emptyProtectedU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxJWSProtectedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty protected header: %w", err)
	}

	emptyCertTBSU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, MaxCertTBSBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty certificate TBS: %w", err)
	}

	emptyHashU8, err := zkcore.BytesToU8ArrayWithPadding([]byte{}, SHA256DigestSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create empty hash: %w", err)
	}

	var hashArray [SHA256DigestSize]uints.U8
	copy(hashArray[:], emptyHashU8)

	// Create zero field elements for signatures and keys
	zeroR := emulated.ValueOf[Secp256r1Fr](0)
	zeroS := emulated.ValueOf[Secp256r1Fr](0)
	zeroX := emulated.ValueOf[Secp256r1Fp](0)
	zeroY := emulated.ValueOf[Secp256r1Fp](0)

	// Step 3: Return circuit with only public inputs populated
	return &Circuit{
		// Empty private inputs
		JWSProtected:   emptyProtectedU8,
		ProtectedSize:  0,
		JWSSigR:        zeroR,
		JWSSigS:        zeroS,
		SignerPubKeyX:  zeroX,
		SignerPubKeyY:  zeroY,
		CertTBSDER:     emptyCertTBSU8,
		CertTBSDERSize: 0,
		CertSigR:       zeroR,
		CertSigS:       zeroS,
		Hash:           hashArray,

		// Public inputs
		JWSPayload:  jwsPayloadU8,
		PayloadSize: len(w.JWSPayload),
		QTSPPubKeyX: qtspPubKeyX,
		QTSPPubKeyY: qtspPubKeyY,
	}, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs
// These are the secret values the prover knows but doesn't want to reveal
type PrivateInput struct {
	// Protected is the complete base64url-encoded JWS protected header
	// Example: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"
	Protected string `json:"protected" description:"BASE64URL encoded JWS protected header"`

	// Signature is the base64url-encoded JWS signature value (R || S, 64 bytes
	// total)
	// Example: "MEUCIQDxK..." (contains both R and S components concatenated)
	Signature string `json:"signature" description:"BASE64URL encoded JWS signature value (ES256)"`

	// X5C is the PEM-encoded X.509 certificate containing the signer's public
	// key
	// This certificate was issued and signed by the QTSP
	// Example: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
	X5C string `json:"x5c" description:"PEM encoded X.509 certificate"`

	// Hash is the SHA-256 hash of the JWS signing input (Protected + "." +
	// Payload)
	// Pre-computed to reduce circuit complexity
	Hash string `json:"hash" description:"BASE64URL encoded SHA-256 hash of Protected.Payload"`
}

// PublicInput defines the JSON structure for public inputs
// This is what the verifier needs to know
type PublicInput struct {
	// Payload is the base64url-encoded JWS payload (the actual signed data)
	// This is publicly revealed - we prove the signature is valid for this data
	// Example: "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
	Payload string `json:"payload" description:"BASE64URL encoded JWS payload"`

	// QTSPPublicKey is the PEM-encoded public key of the Qualified Trust
	// Service Provider
	// This is the trust anchor - everyone knows and trusts this key
	// Example: "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----"
	QTSPPublicKey string `json:"qtspPublicKey" description:"PEM encoded QTSP public key (trust anchor)"`
}

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"protected": {
		Max: MaxJWSProtectedBytes,
	},
	"payload": {
		Max: MaxJWSPayloadBytes,
	},
	"x5c": {
		Max: MaxCertTBSBytes,
	},
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a ZK proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (payload and QTSP key)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (JWS components and certificate)"`
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
// HELPER FUNCTIONS - Parse cryptographic data from various formats
// ========================================================================

// parseJWSSignature decodes a base64url encoded JWS signature and extracts R
// and S components
// JWS ES256 signatures are exactly 64 bytes: 32 bytes for R + 32 bytes for S
// This follows RFC 7515 section 3.4 (JWS Signature)
func parseJWSSignature(signatureB64 string) (r, s *big.Int, err error) {
	// Decode from base64url to raw bytes
	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode signature from base64url: %w", err)
	}

	// Validate signature length
	if len(sigBytes) != 64 {
		return nil, nil, fmt.Errorf("invalid ES256 signature length: expected 64 bytes, got %d", len(sigBytes))
	}

	// Split into R (first 32 bytes) and S (last 32 bytes)
	r = new(big.Int).SetBytes(sigBytes[:32])
	s = new(big.Int).SetBytes(sigBytes[32:])

	return r, s, nil
}

// parsePEMPublicKey parses a PEM encoded ECDSA public key and extracts X and Y
// coordinates
// PEM format: Base64-encoded DER data wrapped in "-----BEGIN PUBLIC KEY-----"
// markers
func parsePEMPublicKey(pemData string) (x, y *big.Int, err error) {
	// Step 1: Decode PEM block to get DER bytes
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block: invalid PEM format")
	}

	// Step 2: Parse the DER-encoded public key
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	// Step 3: Type assert to ECDSA public key
	ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not an ECDSA key (got %T)", pubKeyInterface)
	}

	// Step 4: Extract X and Y coordinates
	return ecdsaPubKey.X, ecdsaPubKey.Y, nil
}

// parsePEMCertificate parses a PEM encoded X.509 certificate and extracts all needed components
// This extracts:
// - TBS (To Be Signed): The certificate data that was signed by the issuer
// - Signature (R, S): The ECDSA signature created by the issuer (QTSP)
// - Public Key (X, Y): The subject's public key embedded in the certificate
func parsePEMCertificate(pemData string) (tbsDER []byte, sigR, sigS *big.Int, pubKeyX, pubKeyY *big.Int, err error) {
	// Step 1: Decode PEM block to get DER bytes
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decode PEM block: invalid PEM format")
	}

	// Step 2: Parse the complete certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Step 3: Extract TBSCertificate (To Be Signed portion)
	// The certificate structure is: Certificate = TBSCertificate || SignatureAlgorithm || SignatureValue
	// We need to parse the raw ASN.1 structure to extract just the TBS bytes
	var certStruct struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}

	_, err = asn1.Unmarshal(block.Bytes, &certStruct)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to unmarshal ASN.1 certificate structure: %w", err)
	}

	// Extract the full TBS bytes (this is what gets hashed and signed)
	tbsDER = certStruct.TBSCertificate.FullBytes

	// Step 4: Extract ECDSA signature components (R, S) from the signature value
	// The signature is ASN.1 encoded as: SEQUENCE { r INTEGER, s INTEGER }
	var ecdsaSig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(certStruct.SignatureValue.Bytes, &ecdsaSig)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to parse ECDSA signature from certificate: %w", err)
	}
	sigR = ecdsaSig.R
	sigS = ecdsaSig.S

	// Step 5: Extract the subject's public key from the certificate
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, nil, nil, fmt.Errorf("certificate does not contain an ECDSA public key (got %T)", cert.PublicKey)
	}
	pubKeyX = ecdsaPubKey.X
	pubKeyY = ecdsaPubKey.Y

	return tbsDER, sigR, sigS, pubKeyX, pubKeyY, nil
}

// ========================================================================
// INPUT PARSER - Converts API JSON to circuit format
// ========================================================================

// parseAPIRequest converts simplified API inputs into WitnessInput format
// This bridges the gap between user-friendly JSON API and circuit-specific format
func parseAPIRequest(publicInput PublicInput, privateInput *PrivateInput) (*WitnessInput, error) {
	// Initialize witness with public inputs
	witness := &WitnessInput{
		JWSPayload: publicInput.Payload,
	}

	// Step 1: Parse QTSP public key (the trust anchor)
	qtspX, qtspY, err := parsePEMPublicKey(publicInput.QTSPPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QTSP public key: %w", err)
	}
	witness.QTSPPubKeyX = qtspX
	witness.QTSPPubKeyY = qtspY

	// If no private input provided, return witness with only public data
	// This is used for verification (verifier doesn't need private inputs)
	if privateInput == nil {
		return witness, nil
	}

	// Step 2: Parse JWS signature (R and S components)
	jwsSigR, jwsSigS, err := parseJWSSignature(privateInput.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS signature: %w", err)
	}
	witness.JWSSigR = jwsSigR
	witness.JWSSigS = jwsSigS

	// Step 3: Set JWS protected header (kept as base64url string)
	witness.JWSProtected = privateInput.Protected

	// Step 4: Parse X.509 certificate to extract all components
	certTBS, certSigR, certSigS, signerPubX, signerPubY, err := parsePEMCertificate(privateInput.X5C)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Step 5: Encode certificate TBS as base64url for circuit processing
	witness.CertTBSDER = base64.RawURLEncoding.EncodeToString(certTBS)
	witness.CertSigR = certSigR
	witness.CertSigS = certSigS
	witness.SignerPubKeyX = signerPubX
	witness.SignerPubKeyY = signerPubY

	// Step 6: Set the pre-computed hash
	witness.Hash = privateInput.Hash

	return witness, nil
}

// ========================================================================
// INPUT PARSER IMPLEMENTATION
// ========================================================================

// API implements the InputParser interface for the JWS certificate verification circuit
type API struct{}

// Parse parses the HTTP API inputs to ZK Circuit inputs
// This is called by the framework to convert JSON payloads into circuit witnesses
func (api *API) Parse(publicInputJSON, privateInputJSON []byte) (frontend.Circuit, error) {
	// Step 1: Parse public input JSON
	var publicInput PublicInput
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	// Step 2: Check if this is a verification request (no private inputs)
	if privateInputJSON == nil {
		witness, err := parseAPIRequest(publicInput, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public inputs: %w", err)
		}
		return witness.CreatePublicWitness()
	}

	// Step 3: Parse private input JSON (for proof generation)
	var privateInput PrivateInput
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	// Step 4: Convert API request to witness format
	witness, err := parseAPIRequest(publicInput, &privateInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API request: %w", err)
	}

	// Step 5: Create full circuit witness
	return witness.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Info contains all metadata needed to register this circuit
var Info = &circuits.CircuitInfo{
	// Circuit version
	Version: 1,

	// Circuit template with appropriately sized arrays
	Circuit: &Circuit{
		JWSProtected: make([]uints.U8, MaxJWSProtectedBytes), // JWS protected header
		JWSPayload:   make([]uints.U8, MaxJWSPayloadBytes),   // JWS payload
		CertTBSDER:   make([]uints.U8, MaxCertTBSBytes),      // X.509 certificate TBS
	},

	Name: "verify-jws-cert",

	Description: "Proves JWS signature validity with X.509 certificate chain verification from a Qualified Trust Service Provider (QTSP) without revealing the signer's identity or complete certificate. Verifies: (1) JWS signature is valid, (2) certificate is signed by QTSP, (3) public key binding between JWS and certificate.",

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
