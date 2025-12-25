package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

var (
	ErrInvalidProof          = errors.New("invalid proof")
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrExpiredPresentation   = errors.New("presentation has expired")
	ErrInvalidCircuitID      = errors.New("invalid circuit ID")
	ErrVerifyingKeyMismatch  = errors.New("verifying key hash mismatch")
	ErrMissingRequiredFields = errors.New("missing required fields")
	ErrInvalidPublicInputs   = errors.New("invalid public inputs")
	ErrPublicInputMismatch   = errors.New("public input mismatch with claimed values")
)

// CircuitPublicInputs represents the values that were proven in the ZK circuit
// These are the PUBLIC INPUTS to the circuit that the proof demonstrates knowledge of
type CircuitPublicInputs struct {
	// Values proven by the circuit (not just claimed)
	Issuer           string `json:"issuer"`             // Hash or identifier of credential issuer
	Audience         string `json:"audience,omitempty"` // Intended recipient
	IssuedAt         int64  `json:"issued_at"`          // Timestamp when credential was issued
	ExpiresAt        int64  `json:"expires_at"`         // Credential expiration
	Nonce            string `json:"nonce,omitempty"`    // Challenge nonce
	Domain           string `json:"domain,omitempty"`   // Application domain
	CredentialHash   string `json:"credential_hash"`    // Hash of the credential being proven
	SubjectID        string `json:"subject_id"`         // Subject identifier (may be hidden via hash)
	ClaimHash        string `json:"claim_hash"`         // Hash of claims being proven
	RevocationStatus string `json:"revocation_status"`  // Revocation registry state

	// Additional circuit-specific outputs
	// e.g., "age_over_18": true, "citizenship_hash": "0x123..."
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// ZkPresentation represents a complete zero-knowledge proof presentation
type ZkPresentation struct {
	Protected string `json:"protected"` // Base64URL(ProtectedHeader)
	Payload   string `json:"payload"`   // Base64URL(Payload)
	Proof     string `json:"proof"`     // Base64URL(ZK Proof bytes)
	Signature string `json:"signature"` // Base64URL(Signature over protected.payload.proof)
}

// ProtectedHeader contains integrity-protected metadata
type ProtectedHeader struct {
	Alg   string   `json:"alg"`            // Signature algorithm (e.g., "EdDSA", "ES256")
	Typ   string   `json:"typ"`            // Media type: "zkp+json"
	Kid   string   `json:"kid"`            // Key ID for signature verification
	ZkAlg string   `json:"zk_alg"`         // ZK algorithm: "groth16"
	Curve string   `json:"curve"`          // Elliptic curve: "bn254", "bls12-381"
	Crit  []string `json:"crit,omitempty"` // Critical extensions
}

// PresentationPayload contains the proof metadata and public circuit inputs
type PresentationPayload struct {
	// Presentation metadata (not proven in circuit, but signed)
	Jti       string `json:"jti"`        // Unique presentation ID
	CreatedAt int64  `json:"created_at"` // When this presentation was created
	CircuitID string `json:"circuit_id"` // Unique circuit identifier
	VkHash    string `json:"vk_hash"`    // SHA-256 hash of verifying key

	// The actual PUBLIC INPUTS to the ZK circuit
	// These values were PROVEN by the circuit, not just claimed
	PublicInputs CircuitPublicInputs `json:"public_inputs"`

	// Raw public inputs as field elements (for verification)
	// This is the actual witness data that the proof verifies
	RawInputs []string `json:"raw_inputs"`

	// Schema information
	InputSchema string `json:"input_schema"` // Schema version for interpreting inputs

	// Optional: embedded VK for standalone verification (testing only)
	VkEmbed []byte `json:"vk_embed,omitempty"`
}

// PresentationBuilder constructs secure presentations
type PresentationBuilder struct {
	registry ZKCircuitRegistry
	signer   Signer
	curve    ecc.ID
}

// NewPresentationBuilder creates a new builder with required dependencies
func NewPresentationBuilder(
	registry ZKCircuitRegistry,
	signer Signer,
	curve ecc.ID,
) *PresentationBuilder {
	return &PresentationBuilder{
		registry: registry,
		signer:   signer,
		curve:    curve,
	}
}

// BuildOptions contains options for building a presentation
type BuildOptions struct {
	CircuitID           string // Required: identifies the circuit
	IncludeVerifyingKey bool   // Whether to embed VK (testing only)
	PresentationID      string // Optional: custom presentation ID
}

// Build creates a cryptographically secured presentation
// The publicInputs parameter contains the PROVEN values from the circuit
func (b *PresentationBuilder) Build(
	opts BuildOptions,
	publicInputs CircuitPublicInputs,
	rawInputs []string,
	inputSchema string,
	proof groth16.Proof,
	vk groth16.VerifyingKey,
) (*ZkPresentation, error) {
	// Validate inputs
	if err := b.validateInputs(opts.CircuitID, publicInputs, rawInputs); err != nil {
		return nil, err
	}

	// Compute verifying key hash
	vkHash, err := computeVerifyingKeyHash(vk)
	if err != nil {
		return nil, fmt.Errorf("failed to compute VK hash: %w", err)
	}

	// Register or verify VK in registry
	registeredHash, err := b.registry.RegisterVerifyingKey(vk, opts.CircuitID)
	if err != nil {
		return nil, fmt.Errorf("failed to register VK: %w", err)
	}
	if registeredHash != vkHash {
		return nil, fmt.Errorf("VK hash mismatch: computed=%s, registered=%s", vkHash, registeredHash)
	}

	// Build protected header
	protected := ProtectedHeader{
		Alg:   "EdDSA", // Or extract from signer
		Typ:   "zkp+json",
		Kid:   b.signer.GetKeyID(),
		ZkAlg: "groth16",
		Curve: b.curve.String(),
	}

	protectedBytes, err := json.Marshal(protected)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protected header: %w", err)
	}
	protectedEncoded := base64.RawURLEncoding.EncodeToString(protectedBytes)

	// Generate presentation ID
	jti := opts.PresentationID
	if jti == "" {
		jti = generatePresentationID()
	}

	// Build payload
	payload := PresentationPayload{
		Jti:          jti,
		CreatedAt:    time.Now().Unix(),
		CircuitID:    opts.CircuitID,
		VkHash:       vkHash,
		PublicInputs: publicInputs,
		RawInputs:    rawInputs,
		InputSchema:  inputSchema,
	}

	// Optionally embed VK (only for testing/standalone scenarios)
	if opts.IncludeVerifyingKey {
		var vkBuf bytes.Buffer
		if _, err := vk.WriteTo(&vkBuf); err != nil {
			return nil, fmt.Errorf("failed to serialize VK: %w", err)
		}
		payload.VkEmbed = vkBuf.Bytes()
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Serialize proof
	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %w", err)
	}
	proofEncoded := base64.RawURLEncoding.EncodeToString(proofBuf.Bytes())

	// Create signing input: protected.payload.proof
	signingInput := fmt.Sprintf("%s.%s.%s", protectedEncoded, payloadEncoded, proofEncoded)

	// Sign the presentation
	signature, err := b.signer.Sign([]byte(signingInput))
	if err != nil {
		return nil, fmt.Errorf("failed to sign presentation: %w", err)
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return &ZkPresentation{
		Protected: protectedEncoded,
		Payload:   payloadEncoded,
		Proof:     proofEncoded,
		Signature: signatureEncoded,
	}, nil
}

// validateInputs performs input validation
func (b *PresentationBuilder) validateInputs(
	circuitID string,
	publicInputs CircuitPublicInputs,
	rawInputs []string,
) error {
	if circuitID == "" {
		return fmt.Errorf("%w: circuit_id is required", ErrMissingRequiredFields)
	}
	if len(rawInputs) == 0 {
		return fmt.Errorf("%w: raw inputs cannot be empty", ErrInvalidPublicInputs)
	}
	if publicInputs.Issuer == "" {
		return fmt.Errorf("%w: issuer is required", ErrMissingRequiredFields)
	}
	if publicInputs.CredentialHash == "" {
		return fmt.Errorf("%w: credential_hash is required", ErrMissingRequiredFields)
	}
	return nil
}

// PresentationVerifier verifies presentations
type PresentationVerifier struct {
	registry       ZKCircuitRegistry
	verifier       Verifier
	inputValidator InputValidator
}

// InputValidator validates that structured inputs match raw witness values
type InputValidator interface {
	// ValidateInputs checks that the structured public inputs correctly represent
	// the raw circuit witness values according to the circuit's input schema
	ValidateInputs(structured CircuitPublicInputs, raw []string, schema string) error
}

// NewPresentationVerifier creates a new verifier
func NewPresentationVerifier(
	registry ZKCircuitRegistry,
	verifier Verifier,
	validator InputValidator,
) *PresentationVerifier {
	return &PresentationVerifier{
		registry:       registry,
		verifier:       verifier,
		inputValidator: validator,
	}
}

// VerificationOptions provides options for verification
type VerificationOptions struct {
	// Values to check against the PROVEN public inputs
	ExpectedIssuer   string // Expected issuer (must match proven value)
	ExpectedAudience string // Expected audience (must match proven value)
	ExpectedDomain   string // Expected domain (must match proven value)
	ExpectedNonce    string // Expected nonce (must match proven value)

	// Time validation
	CurrentTime  time.Time // For testing with fixed time
	AllowExpired bool      // Allow expired credentials (for testing)

	// Additional constraints
	RequiredAttributes map[string]interface{} // Attributes that must be present
}

// VerificationResult contains the verified presentation data
type VerificationResult struct {
	Payload      *PresentationPayload
	PublicInputs *CircuitPublicInputs
	IsValid      bool
	ValidatedAt  time.Time
}

// Verify performs complete verification of a presentation
func (v *PresentationVerifier) Verify(
	presentation *ZkPresentation,
	opts VerificationOptions,
) (*VerificationResult, error) {
	// Decode and parse protected header
	protectedBytes, err := base64.RawURLEncoding.DecodeString(presentation.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to decode protected header: %w", err)
	}
	var protected ProtectedHeader
	if err := json.Unmarshal(protectedBytes, &protected); err != nil {
		return nil, fmt.Errorf("failed to parse protected header: %w", err)
	}

	// Verify media type
	if protected.Typ != "zkp+json" {
		return nil, fmt.Errorf("invalid type: expected zkp+json, got %s", protected.Typ)
	}

	// Decode and parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(presentation.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload PresentationPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Verify signature over the entire presentation
	signingInput := fmt.Sprintf("%s.%s.%s",
		presentation.Protected,
		presentation.Payload,
		presentation.Proof)
	signatureBytes, err := base64.RawURLEncoding.DecodeString(presentation.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	if err := v.verifier.Verify([]byte(signingInput), signatureBytes, protected.Kid); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// CRITICAL: Validate that structured inputs match raw circuit inputs
	// This prevents attacks where someone claims different values than what was proven
	if v.inputValidator != nil {
		if err := v.inputValidator.ValidateInputs(
			payload.PublicInputs,
			payload.RawInputs,
			payload.InputSchema,
		); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPublicInputMismatch, err)
		}
	}

	// Verify the PROVEN public inputs against expected values
	if err := v.verifyProvenInputs(&payload.PublicInputs, opts); err != nil {
		return nil, err
	}

	// Retrieve verifying key
	vk, err := v.registry.GetVerifyingKey(payload.VkHash)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve verifying key: %w", err)
	}

	// Verify VK hash matches
	computedHash, err := computeVerifyingKeyHash(vk)
	if err != nil {
		return nil, fmt.Errorf("failed to compute VK hash: %w", err)
	}
	if computedHash != payload.VkHash {
		return nil, ErrVerifyingKeyMismatch
	}

	// Decode proof
	proofBytes, err := base64.RawURLEncoding.DecodeString(presentation.Proof)
	if err != nil {
		return nil, fmt.Errorf("failed to decode proof: %w", err)
	}
	proof := groth16.NewProof(getCurveFromString(protected.Curve))
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Convert raw inputs to witness
	witness, err := rawInputsToWitness(payload.RawInputs, getCurveFromString(protected.Curve))
	if err != nil {
		return nil, fmt.Errorf("failed to convert inputs to witness: %w", err)
	}

	// Verify the ZK proof - THIS IS WHERE WE VERIFY THE CIRCUIT PROVED THE VALUES
	if err := groth16.Verify(proof, vk, witness); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}

	return &VerificationResult{
		Payload:      &payload,
		PublicInputs: &payload.PublicInputs,
		IsValid:      true,
		ValidatedAt:  time.Now(),
	}, nil
}

// verifyProvenInputs validates the values that were PROVEN by the circuit
func (v *PresentationVerifier) verifyProvenInputs(
	inputs *CircuitPublicInputs,
	opts VerificationOptions,
) error {
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	// Check expiration of the PROVEN credential
	if !opts.AllowExpired && now.Unix() > inputs.ExpiresAt {
		return fmt.Errorf("%w: credential expired at %d, now is %d",
			ErrExpiredPresentation, inputs.ExpiresAt, now.Unix())
	}

	// Verify the PROVEN issuer matches expected
	if opts.ExpectedIssuer != "" && inputs.Issuer != opts.ExpectedIssuer {
		return fmt.Errorf("issuer mismatch: expected %s, proven %s",
			opts.ExpectedIssuer, inputs.Issuer)
	}

	// Verify the PROVEN audience matches expected
	if opts.ExpectedAudience != "" && inputs.Audience != opts.ExpectedAudience {
		return fmt.Errorf("audience mismatch: expected %s, proven %s",
			opts.ExpectedAudience, inputs.Audience)
	}

	// Verify the PROVEN domain matches expected
	if opts.ExpectedDomain != "" && inputs.Domain != opts.ExpectedDomain {
		return fmt.Errorf("domain mismatch: expected %s, proven %s",
			opts.ExpectedDomain, inputs.Domain)
	}

	// Verify the PROVEN nonce matches expected
	if opts.ExpectedNonce != "" && inputs.Nonce != opts.ExpectedNonce {
		return fmt.Errorf("nonce mismatch: expected %s, proven %s",
			opts.ExpectedNonce, inputs.Nonce)
	}

	// Check required attributes are present in proven data
	for key, expectedValue := range opts.RequiredAttributes {
		actualValue, exists := inputs.Attributes[key]
		if !exists {
			return fmt.Errorf("required attribute %s not found in proven inputs", key)
		}
		if expectedValue != nil && actualValue != expectedValue {
			return fmt.Errorf("attribute %s mismatch: expected %v, proven %v",
				key, expectedValue, actualValue)
		}
	}

	return nil
}

// Utility functions

func computeVerifyingKeyHash(vk groth16.VerifyingKey) (string, error) {
	var buf bytes.Buffer
	if _, err := vk.WriteTo(&buf); err != nil {
		return "", err
	}
	hash := sha256.Sum256(buf.Bytes())
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func getCurveFromString(curve string) ecc.ID {
	switch curve {
	case "bn254":
		return ecc.BN254
	case "bls12-381":
		return ecc.BLS12_381
	case "bls12-377":
		return ecc.BLS12_377
	default:
		return ecc.BN254 // Default
	}
}

func generatePresentationID() string {
	// Generate a unique presentation ID (e.g., UUID)
	// This is a placeholder - use a proper UUID library
	return fmt.Sprintf("pres_%d", time.Now().UnixNano())
}

// rawInputsToWitness converts raw field element strings to gnark witness
func rawInputsToWitness(rawInputs []string, curve ecc.ID) (witness.Witness, error) {
	// This is circuit-specific and needs to be implemented based on your circuit
	// The raw inputs should be field elements as decimal or hex strings
	// that match the public input ordering of your circuit
	return nil, errors.New("not implemented: convert raw inputs to witness based on circuit")
}
