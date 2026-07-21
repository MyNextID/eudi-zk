// Package assertfacematch contains a ZK circuit that proves a public face
// embedding is "close enough" (within a public threshold) to a private
// reference face embedding, without revealing the private embedding.
package assertfacematch

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/circuits"
)

// ========================================================================
// CIRCUIT CONSTANTS
// ========================================================================

const (
	// EmbeddingLen is the length of the face embedding vector.
	// Common values: 128 (FaceNet/dlib), 512 (ArcFace). Adjust to match
	// whatever face-recognition model produced the embeddings.
	EmbeddingLen = 128

	// FixedPointScale converts floating point embedding coordinates
	// (typically in roughly [-1, 1] for L2-normalized embeddings) into
	// integers the circuit can operate on. value_fixed = round(value * Scale).
	FixedPointScale = 1 << 16 // 65536

	// MaxCoordAbs bounds the absolute value of any single *scaled* embedding
	// coordinate. Used to reject malformed/adversarial inputs before they
	// ever reach the circuit, and to reason about the maximum possible
	// squared distance so we know it fits comfortably under the scalar
	// field modulus with no wraparound risk.
	//
	// For L2-normalized embeddings, |coord| <= 1, so scaled coord magnitude
	// is bounded by FixedPointScale. We allow a bit of headroom.
	MaxCoordAbs = 4 * FixedPointScale

	// MaxThreshold bounds the raw (unscaled) linear distance threshold.
	// For L2-normalized embeddings, the maximum possible true Euclidean
	// distance between any two unit vectors is 2 (they'd have to point in
	// exactly opposite directions). We allow some headroom above that so
	// legitimate thresholds are never rejected, while still keeping
	// squaredThreshold() well clear of int64/field overflow.
	MaxThreshold = 4.0

	// NormTolerance is how far sum(coord^2) may deviate from 1.0 before an
	// embedding is rejected as "not L2-normalized." This circuit's
	// squared-distance-vs-squared-threshold comparison only has the
	// semantics of "cosine-similarity-like closeness" when both vectors
	// are unit-normalized; this is a sanity check, not a cryptographic
	// property, and is enforced in Go before witness generation rather
	// than inside the circuit (the circuit has no way to know what
	// "normalized" means for a caller's model).
	NormTolerance = 0.05
)

// ========================================================================
// CIRCUIT DEFINITION
// ========================================================================

// DescriptionLong is a long circuit description
const DescriptionLong = `
CircuitFaceMatch defines a zero-knowledge circuit that proves a public
("probe") face embedding is within a public distance threshold of a private
("reference") face embedding, without revealing the reference embedding.

The circuit:
1. Takes a secret, fixed-point-quantized face embedding vector (the
reference) as private witness
2. Takes a public, fixed-point-quantized face embedding vector (the probe)
as public input
3. Takes a public squared-distance threshold as public input
4. Computes the squared Euclidean distance between the two embeddings
5. Asserts that squared distance <= squared threshold

Because floating point, square roots, and division are all expensive or
unavailable in R1CS arithmetic, this circuit intentionally works with:
  - fixed-point (scaled integer) coordinates instead of floats
  - *squared* Euclidean distance instead of true Euclidean distance
  - a *squared* threshold instead of a linear one

so that the entire comparison reduces to subtraction, multiplication, and a
single range-check-based inequality assertion.

Trust assumption about the reference embedding: this circuit assumes the
prover supplies ReferenceEmbedding as extracted from a digitally signed e-ID
credential. The circuit itself does not check any signature over the
reference embedding, and does not know or care where it came from - that
trust boundary lives entirely outside this package. This assumption rules
out one specific attack (a party fabricating an arbitrary "reference" to
forge a match), because any reference used has to trace back to a genuine,
signed credential.

The public probe embedding carries no such assumption - it may come from an
unattested source at the point of verification (e.g. a live face-scanning
device).

This circuit also does not bind proofs to a session, nonce, or liveness
check; replay of a captured proof (or a captured quantized reference
embedding) is a concern for the calling protocol, not something this
circuit addresses.
`

// CircuitFaceMatch proves knowledge of a private reference embedding that
// matches a public probe embedding within a public threshold.
type CircuitFaceMatch struct {
	// ===== SECRET INPUT (Private Witness) =====

	// ReferenceEmbedding is the fixed-point-quantized reference embedding,
	// extracted from an e-ID or other signed credential. Coordinates may be
	// negative (field arithmetic handles this natively via modular
	// wraparound, since the field is astronomically larger than the values
	// involved).
	ReferenceEmbedding [EmbeddingLen]frontend.Variable `gnark:",secret"`

	// ===== PUBLIC INPUTS (Visible to Verifier) =====

	// ProbeEmbedding is the fixed-point-quantized embedding being checked
	// against the private reference (e.g. captured live at the point of
	// verification). Carries no provenance assumption of its own.
	ProbeEmbedding [EmbeddingLen]frontend.Variable `gnark:",public"`

	// Threshold2 is the *squared* maximum allowed distance, in the same
	// fixed-point scale as the embeddings (i.e. scaled by FixedPointScale^2).
	Threshold2 frontend.Variable `gnark:",public"`
}

// Define defines the circuit logic
//
// In this circuit, we prove: "I know a reference embedding R such that
//
//	sum_i (R_i - P_i)^2 <= Threshold2"
//
// where P is the public probe embedding and Threshold2 is the public
// squared distance threshold.
func (c *CircuitFaceMatch) Define(api frontend.API) error {
	// Step 1: accumulate squared distance across all dimensions.
	dist2 := frontend.Variable(0)
	for i := range EmbeddingLen {
		diff := api.Sub(c.ReferenceEmbedding[i], c.ProbeEmbedding[i])
		sq := api.Mul(diff, diff)
		dist2 = api.Add(dist2, sq)
	}

	// Step 2: assert the computed squared distance does not exceed the
	// public squared threshold. AssertIsLessOrEqual fails the circuit
	// (proof cannot be generated) if dist2 > Threshold2.
	api.AssertIsLessOrEqual(dist2, c.Threshold2)

	return nil
}

// ========================================================================
// WITNESS INPUT STRUCTS
// ========================================================================

// WitnessInput holds raw floating-point inputs before quantization and
// conversion to circuit witness values.
type WitnessInput struct {
	// Private input - raw reference embedding (unscaled floats), assumed to
	// be sourced from a signed e-ID credential. nil in the verification-only
	// case (no private witness available).
	ReferenceEmbedding []float64

	// Public inputs - raw probe embedding (unscaled floats, e.g. from a live
	// face scan; no provenance assumed) and the (unscaled, linear) distance
	// threshold. Always required.
	ProbeEmbedding []float64
	Threshold      float64
}

// quantize scales and rounds a single float coordinate to a fixed-point
// integer, preserving sign. It rejects non-finite input and any value
// that would overflow int64 on the `v * FixedPointScale` conversion,
// since that conversion is implementation-defined (silently wraps/garbage,
// does not panic) in Go for out-of-range floats.
func quantize(v float64) (*big.Int, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("value is not finite: %v", v)
	}

	scaled := math.Round(v * FixedPointScale)

	// Guard the float64 -> int64 cast: reject anything outside int64 range
	// *before* the conversion, rather than relying on the bounds check
	// that runs after quantization (which could pass on wrapped garbage).
	if scaled < math.MinInt64 || scaled > math.MaxInt64 {
		return nil, fmt.Errorf("value out of range after scaling: %v (scaled %v)", v, scaled)
	}

	return big.NewInt(int64(scaled)), nil
}

// quantizeVector quantizes an entire embedding vector.
func quantizeVector(vec []float64) ([]*big.Int, error) {
	out := make([]*big.Int, len(vec))
	for i, v := range vec {
		q, err := quantize(v)
		if err != nil {
			return nil, fmt.Errorf("coordinate %d: %w", i, err)
		}
		out[i] = q
	}
	return out, nil
}

// squaredThreshold computes Threshold2 = round(Threshold * Scale)^2 as a
// big.Int, matching the fixed-point scale used for the embeddings.
func (w *WitnessInput) squaredThreshold() (*big.Int, error) {
	scaledThreshold, err := quantize(w.Threshold)
	if err != nil {
		return nil, fmt.Errorf("threshold: %w", err)
	}
	t2 := new(big.Int).Mul(scaledThreshold, scaledThreshold)
	return t2, nil
}

// checkNormalized verifies that a raw (unscaled) embedding is approximately
// L2-normalized, i.e. sum(coord^2) ~= 1, within NormTolerance. The
// squared-distance-vs-squared-threshold comparison this circuit performs
// only behaves like a meaningful similarity check when both embeddings are
// unit vectors; an unnormalized embedding would silently change what the
// threshold means.
func checkNormalized(name string, vec []float64) error {
	sumSq := 0.0
	for _, v := range vec {
		sumSq += v * v
	}
	if math.Abs(sumSq-1.0) > NormTolerance {
		return fmt.Errorf("%s does not appear to be L2-normalized: sum(coord^2) = %f (expected ~1.0 +/- %f)",
			name, sumSq, NormTolerance)
	}
	return nil
}

// Validate performs input validation. ProbeEmbedding (public) is always
// required; ReferenceEmbedding (private) is only present in the proving
// case and is nil for verification-only witnesses.
func (w *WitnessInput) Validate() error {
	if len(w.ProbeEmbedding) != EmbeddingLen {
		return fmt.Errorf("probe embedding must have %d dimensions, got %d",
			EmbeddingLen, len(w.ProbeEmbedding))
	}
	if w.ReferenceEmbedding != nil && len(w.ReferenceEmbedding) != EmbeddingLen {
		return fmt.Errorf("reference embedding must have %d dimensions, got %d",
			EmbeddingLen, len(w.ReferenceEmbedding))
	}
	if math.IsNaN(w.Threshold) || math.IsInf(w.Threshold, 0) {
		return fmt.Errorf("threshold is not finite: %v", w.Threshold)
	}
	if w.Threshold < 0 {
		return fmt.Errorf("threshold must be non-negative, got %f", w.Threshold)
	}
	if w.Threshold > MaxThreshold {
		return fmt.Errorf("threshold %f exceeds maximum allowed %f", w.Threshold, MaxThreshold)
	}

	maxAbs := big.NewInt(MaxCoordAbs)
	checkBounds := func(name string, vec []float64) error {
		for i, v := range vec {
			q, err := quantize(v)
			if err != nil {
				return fmt.Errorf("%s coordinate %d: %w", name, i, err)
			}
			if q.CmpAbs(maxAbs) > 0 {
				return fmt.Errorf("%s coordinate %d out of bounds after quantization: %s (max abs %s)",
					name, i, q.String(), maxAbs.String())
			}
		}
		return nil
	}
	if err := checkBounds("probe embedding", w.ProbeEmbedding); err != nil {
		return err
	}
	if err := checkNormalized("probe embedding", w.ProbeEmbedding); err != nil {
		return err
	}
	if w.ReferenceEmbedding != nil {
		if err := checkBounds("reference embedding", w.ReferenceEmbedding); err != nil {
			return err
		}
		if err := checkNormalized("reference embedding", w.ReferenceEmbedding); err != nil {
			return err
		}
	}

	return nil
}

// CreateWitness creates a full witness (private + public) for proving
func (w *WitnessInput) CreateWitness() (frontend.Circuit, error) {
	refQ, err := quantizeVector(w.ReferenceEmbedding)
	if err != nil {
		return nil, fmt.Errorf("failed to quantize reference embedding: %w", err)
	}
	probeQ, err := quantizeVector(w.ProbeEmbedding)
	if err != nil {
		return nil, fmt.Errorf("failed to quantize probe embedding: %w", err)
	}
	t2, err := w.squaredThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to quantize threshold: %w", err)
	}

	var circuit CircuitFaceMatch
	for i := range EmbeddingLen {
		circuit.ReferenceEmbedding[i] = refQ[i]
		circuit.ProbeEmbedding[i] = probeQ[i]
	}
	circuit.Threshold2 = t2

	return &circuit, nil
}

// CreatePublicWitness creates only the public inputs for verification
func (w *WitnessInput) CreatePublicWitness() (frontend.Circuit, error) {
	probeQ, err := quantizeVector(w.ProbeEmbedding)
	if err != nil {
		return nil, fmt.Errorf("failed to quantize probe embedding: %w", err)
	}
	t2, err := w.squaredThreshold()
	if err != nil {
		return nil, fmt.Errorf("failed to quantize threshold: %w", err)
	}

	var circuit CircuitFaceMatch
	for i := range EmbeddingLen {
		// Private field left as zero placeholder; ignored during verification.
		circuit.ReferenceEmbedding[i] = big.NewInt(0)
		circuit.ProbeEmbedding[i] = probeQ[i]
	}
	circuit.Threshold2 = t2

	return &circuit, nil
}

// ========================================================================
// API DATA MODELS - JSON structures for HTTP endpoints
// ========================================================================

// PrivateInput defines the JSON structure for private inputs to the circuit.
// This data is known only to the prover.
type PrivateInput struct {
	// ReferenceEmbedding is the base64url-encoded JSON array of float64
	// embedding coordinates for the reference face, sourced from a
	// verified, digitally signed e-ID credential (see trust-assumption
	// note in DescriptionLong).
	ReferenceEmbedding string `json:"reference_embedding" description:"BASE64URL encoded JSON array of float64 embedding coordinates (reference face, sourced from a verified, digitally signed e-ID credential)"`
}

// PublicInput defines the JSON structure for public inputs to the circuit.
// This data will be visible to anyone verifying the proof.
type PublicInput struct {
	// ProbeEmbedding is the base64url-encoded JSON array of float64
	// embedding coordinates for the face being checked against the
	// reference (e.g. captured by a face-scanning device at the point of
	// verification). Carries no provenance assumption.
	ProbeEmbedding string `json:"probe_embedding" description:"BASE64URL encoded JSON array of float64 embedding coordinates (probe face)"`

	// Threshold is the maximum allowed (unscaled, linear) Euclidean
	// distance between probe and reference embeddings for a match.
	Threshold float64 `json:"threshold" description:"Maximum allowed Euclidean distance between embeddings for a match"`
}

// decodeEmbedding decodes a base64url-encoded JSON float64 array
func decodeEmbedding(encoded string) ([]float64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode embedding: %w", err)
	}
	var vec []float64
	if err := json.Unmarshal(raw, &vec); err != nil {
		return nil, fmt.Errorf("failed to parse embedding JSON: %w", err)
	}
	return vec, nil
}

// ========================================================================
// PROVE ENDPOINT - POST /prove
// ========================================================================

// ProveRequest defines the request body for generating a zero-knowledge proof
type ProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs (probe embedding and threshold)"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs (reference embedding)"`
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
	// Success indicates whether the verification process itself completed
	// without error (distinct from Valid, which indicates whether the
	// proof was mathematically valid).
	Success bool `json:"success"`

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
	var publicInput PublicInput
	if err := json.Unmarshal(publicInputJSON, &publicInput); err != nil {
		return nil, fmt.Errorf("failed to parse public input JSON: %w", err)
	}

	probeEmbedding, err := decodeEmbedding(publicInput.ProbeEmbedding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode probe embedding: %w", err)
	}

	// Handle verification case (no private input)
	if privateInputJSON == nil {
		w := WitnessInput{
			ProbeEmbedding: probeEmbedding,
			Threshold:      publicInput.Threshold,
		}
		if err := w.Validate(); err != nil {
			return nil, fmt.Errorf("public input validation failed: %w", err)
		}
		return w.CreatePublicWitness()
	}

	var privateInput PrivateInput
	if err := json.Unmarshal(privateInputJSON, &privateInput); err != nil {
		return nil, fmt.Errorf("failed to parse private input JSON: %w", err)
	}

	referenceEmbedding, err := decodeEmbedding(privateInput.ReferenceEmbedding)
	if err != nil {
		return nil, fmt.Errorf("failed to decode reference embedding: %w", err)
	}

	w := WitnessInput{
		ReferenceEmbedding: referenceEmbedding,
		ProbeEmbedding:     probeEmbedding,
		Threshold:          publicInput.Threshold,
	}

	if err := w.Validate(); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	return w.CreateWitness()
}

// ========================================================================
// CIRCUIT REGISTRATION - Metadata for the framework
// ========================================================================

// Constraints defines the circuit constraints
var Constraints = map[string]circuits.Constraints{
	"embedding_dim": {
		Max:         EmbeddingLen,
		Description: "Face embedding vector length",
	},
}

// Info contains all metadata needed to register this circuit with the framework
var Info = &circuits.CircuitInfo{
	Name:            "assert-face-match",
	Description:     "Proves a public probe face embedding is within a public distance threshold of a private reference face embedding, without revealing the private reference embedding.",
	LongDescription: DescriptionLong,
	Version:         1,
	Circuit:         &CircuitFaceMatch{},
	InputParser:     &API{},
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
