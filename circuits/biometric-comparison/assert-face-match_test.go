package assertfacematch_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	assertfacematch "github.com/mynextid/eudi-zk/circuits/biometric-comparison"
)

// encodeEmbedding mirrors the decoding done by assertfacematch's input
// parser: a JSON float64 array, base64url encoded.
func encodeEmbedding(vec []float64) string {
	raw, err := json.Marshal(vec)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal embedding: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// normalize rescales vec in place (well, in a copy) to unit L2 norm.
func normalize(vec []float64) []float64 {
	out := make([]float64, len(vec))
	var normSq float64
	for _, v := range vec {
		normSq += v * v
	}
	norm := math.Sqrt(normSq)
	for i, v := range vec {
		out[i] = v / norm
	}
	return out
}

// randomEmbedding generates a deterministic pseudo-random, L2-normalized
// embedding vector of the given dimension.
func randomEmbedding(r *rand.Rand, dim int) []float64 {
	vec := make([]float64, dim)
	for i := range vec {
		vec[i] = r.Float64()*2 - 1 // uniform in [-1, 1]
	}
	return normalize(vec)
}

// perturbEmbedding returns a copy of vec with independent noise of the given
// per-coordinate magnitude added, then re-normalized back to a unit vector.
// Re-normalizing is important: the circuit's threshold semantics (and, since
// the last review round, WitnessInput.Validate) assume both embeddings are
// L2-normalized, so a "close but still a valid embedding" test fixture has
// to preserve that, not just add noise and stop.
func perturbEmbedding(r *rand.Rand, vec []float64, magnitude float64) []float64 {
	out := make([]float64, len(vec))
	for i, v := range vec {
		out[i] = v + (r.Float64()*2-1)*magnitude
	}
	return normalize(out)
}

// euclideanDistance is used only to pick a sensible threshold for the tests
// below; it is not part of the circuit itself (which only ever sees squared,
// fixed-point quantities).
func euclideanDistance(a, b []float64) float64 {
	var sumSq float64
	for i := range a {
		d := a[i] - b[i]
		sumSq += d * d
	}
	return math.Sqrt(sumSq)
}

func TestFaceMatch_WithinThreshold(t *testing.T) {
	saveExamplePayload := true

	// == create dummy data ==
	r := rand.New(rand.NewSource(1))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	probe := perturbEmbedding(r, reference, 0.01) // small perturbation -> same person

	dist := euclideanDistance(reference, probe)
	threshold := dist * 1.5 // comfortably above the actual distance

	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	pvtIn := assertfacematch.PrivateInput{
		ProbeEmbedding: encodeEmbedding(probe),
	}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          threshold,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	// create a proof
	proof, err := zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// verify the proof
	err = zkc.VerifyWithJSON(pubInBuf, proof)
	if err != nil {
		t.Fatalf("failed to verify a proof: %v", err)
	}

	// save the sample payload
	if saveExamplePayload {
		proveRequest := circuits.Request{
			Private: pvtIn,
			Public:  pubIn,
		}
		filename := fmt.Sprintf("%s.json", zkc.Info.Name)
		path := filepath.Join("examples", filename)
		if err := proveRequest.Save(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFaceMatch_ExceedsThreshold(t *testing.T) {
	// == create dummy data ==
	r := rand.New(rand.NewSource(2))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	probe := randomEmbedding(r, assertfacematch.EmbeddingLen) // unrelated embedding -> different person

	dist := euclideanDistance(reference, probe)
	threshold := dist * 0.5 // well below the actual distance, so the proof must fail

	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	pvtIn := assertfacematch.PrivateInput{
		ProbeEmbedding: encodeEmbedding(probe),
	}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          threshold,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	// proving should fail: the circuit's AssertIsLessOrEqual constraint
	// cannot be satisfied when the true distance exceeds the threshold.
	_, err = zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err == nil {
		t.Fatal("expected proof generation to fail for embeddings exceeding the threshold, but it succeeded")
	}
}

func TestFaceMatch_InvalidEmbeddingDimension(t *testing.T) {
	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	r := rand.New(rand.NewSource(3))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	wrongSizeProbe := randomEmbedding(r, assertfacematch.EmbeddingLen/2) // wrong dimension

	pvtIn := assertfacematch.PrivateInput{
		ProbeEmbedding: encodeEmbedding(wrongSizeProbe),
	}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          1.0,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	_, err = zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err == nil {
		t.Fatal("expected proof generation to fail for a mismatched embedding dimension, but it succeeded")
	}
}

// --- Public-input binding: verification must be tied to the exact public
// inputs used when the proof was generated, not just "some valid-looking
// public input of the right shape." ---

func TestFaceMatch_VerifyFailsOnTamperedThreshold(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	probe := perturbEmbedding(r, reference, 0.01)

	dist := euclideanDistance(reference, probe)
	threshold := dist * 1.5

	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	pvtIn := assertfacematch.PrivateInput{ProbeEmbedding: encodeEmbedding(probe)}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          threshold,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	proof, err := zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// Verify against a *different* threshold than the one actually proven.
	// This must fail: otherwise a prover could claim an arbitrarily tight
	// threshold was met just by having the verifier re-check with a looser
	// one after the fact.
	tamperedPubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          threshold * 3, // still <= MaxThreshold, just different
	}
	tamperedPubInBuf, _ := json.Marshal(tamperedPubIn)

	err = zkc.VerifyWithJSON(tamperedPubInBuf, proof)
	if err == nil {
		t.Fatal("expected verification to fail against a tampered threshold, but it succeeded")
	}
}

func TestFaceMatch_VerifyFailsOnMismatchedReference(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	probe := perturbEmbedding(r, reference, 0.01)
	otherReference := randomEmbedding(r, assertfacematch.EmbeddingLen)

	dist := euclideanDistance(reference, probe)
	threshold := dist * 1.5

	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	pvtIn := assertfacematch.PrivateInput{ProbeEmbedding: encodeEmbedding(probe)}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          threshold,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	proof, err := zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// Verify against a swapped-in reference embedding that was never part
	// of the proof. Must fail, otherwise a proof made against one enrolled
	// identity could be replayed as "proof" against a different one.
	swappedPubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(otherReference),
		Threshold:          threshold,
	}
	swappedPubInBuf, _ := json.Marshal(swappedPubIn)

	err = zkc.VerifyWithJSON(swappedPubInBuf, proof)
	if err == nil {
		t.Fatal("expected verification to fail against a mismatched reference embedding, but it succeeded")
	}
}

// --- Input validation added in the last hardening pass. These are checked
// directly against WitnessInput.Validate() rather than through a full
// Compile/Prove cycle: they're testing Go-level input validation, not
// circuit satisfiability, so there's no need to pay for circuit compilation
// and proving in every case. ---

func TestWitnessInput_Validate(t *testing.T) {
	r := rand.New(rand.NewSource(6))
	validRef := randomEmbedding(r, assertfacematch.EmbeddingLen)
	validProbe := perturbEmbedding(r, validRef, 0.01)

	// Perturb one coordinate enough to fail the normalization check
	// (sum(coord^2) off by more than NormTolerance) while staying well
	// inside MaxCoordAbs, so this exercises checkNormalized specifically
	// rather than tripping the (earlier-run) per-coordinate bounds check.
	unnormalized := make([]float64, assertfacematch.EmbeddingLen)
	copy(unnormalized, validRef)
	unnormalized[0] += 0.5

	nonFiniteRef := make([]float64, assertfacematch.EmbeddingLen)
	copy(nonFiniteRef, validRef)
	nonFiniteRef[0] = math.NaN()

	infRef := make([]float64, assertfacematch.EmbeddingLen)
	copy(infRef, validRef)
	infRef[0] = math.Inf(1)

	tests := []struct {
		name      string
		w         assertfacematch.WitnessInput
		wantErr   bool
		errSubstr string // optional: substring expected in the error message
	}{
		{
			name: "valid probe and reference",
			w: assertfacematch.WitnessInput{
				ProbeEmbedding:     validProbe,
				ReferenceEmbedding: validRef,
				Threshold:          0.5,
			},
			wantErr: false,
		},
		{
			name: "valid reference only (verification case, no probe)",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef,
				Threshold:          0.5,
			},
			wantErr: false,
		},
		{
			name: "wrong reference dimension",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef[:assertfacematch.EmbeddingLen-1],
				Threshold:          0.5,
			},
			wantErr:   true,
			errSubstr: "dimensions",
		},
		{
			name: "negative threshold",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef,
				Threshold:          -0.1,
			},
			wantErr:   true,
			errSubstr: "non-negative",
		},
		{
			name: "threshold above MaxThreshold",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef,
				Threshold:          assertfacematch.MaxThreshold + 0.1,
			},
			wantErr:   true,
			errSubstr: "exceeds maximum",
		},
		{
			name: "NaN threshold",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef,
				Threshold:          math.NaN(),
			},
			wantErr:   true,
			errSubstr: "not finite",
		},
		{
			name: "Inf threshold",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: validRef,
				Threshold:          math.Inf(1),
			},
			wantErr:   true,
			errSubstr: "not finite",
		},
		{
			name: "unnormalized reference embedding",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: unnormalized,
				Threshold:          0.5,
			},
			wantErr:   true,
			errSubstr: "normalized",
		},
		{
			name: "unnormalized probe embedding",
			w: assertfacematch.WitnessInput{
				ProbeEmbedding:     unnormalized,
				ReferenceEmbedding: validRef,
				Threshold:          0.5,
			},
			wantErr:   true,
			errSubstr: "normalized",
		},
		{
			name: "non-finite (NaN) coordinate in reference embedding",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: nonFiniteRef,
				Threshold:          0.5,
			},
			wantErr: true,
		},
		{
			name: "non-finite (Inf) coordinate in reference embedding",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: infRef,
				Threshold:          0.5,
			},
			wantErr: true,
		},
		{
			name: "coordinate magnitude beyond MaxCoordAbs after quantization",
			w: assertfacematch.WitnessInput{
				ReferenceEmbedding: func() []float64 {
					v := make([]float64, assertfacematch.EmbeddingLen)
					v[0] = float64(assertfacematch.MaxCoordAbs)/assertfacematch.FixedPointScale + 10
					v[1] = 1 // avoid an all-zero vector tripping normalization first
					return v
				}(),
				Threshold: 0.5,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.w.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if tc.wantErr && err != nil && tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("expected error to contain %q, got: %v", tc.errSubstr, err)
			}
		})
	}
}

// TestFaceMatch_ProveRejectsInvalidThreshold checks the validation wiring
// end-to-end: an out-of-range threshold should be rejected before it ever
// reaches circuit compilation/proving, via the same Parse -> Validate path
// exercised by the /prove HTTP endpoint.
func TestFaceMatch_ProveRejectsInvalidThreshold(t *testing.T) {
	zkc, err := circuits.Compile(assertfacematch.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	r := rand.New(rand.NewSource(7))
	reference := randomEmbedding(r, assertfacematch.EmbeddingLen)
	probe := perturbEmbedding(r, reference, 0.01)

	pvtIn := assertfacematch.PrivateInput{ProbeEmbedding: encodeEmbedding(probe)}
	pvtInBuf, _ := json.Marshal(pvtIn)

	pubIn := assertfacematch.PublicInput{
		ReferenceEmbedding: encodeEmbedding(reference),
		Threshold:          assertfacematch.MaxThreshold + 1, // out of range
	}
	pubInBuf, _ := json.Marshal(pubIn)

	_, err = zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err == nil {
		t.Fatal("expected proof generation to fail for an out-of-range threshold, but it succeeded")
	}
}
