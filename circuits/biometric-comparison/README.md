# Face Match Circuit

Version: 1

## What We Prove

The verification establishes the following properties in a single proof:

1. **Bounded Proximity Match**: The holder possesses a private ("probe") face
embedding whose squared Euclidean distance to a public ("reference") face
embedding is at or under a public squared distance threshold. Both embeddings
are represented as fixed-point (scaled integer) coordinates so the entire
comparison reduces to subtraction, multiplication, and a single
range-check-based inequality assertion inside the circuit.

2. **Privacy Preservation**: All of the above is proven without revealing:
   - the holder's probe embedding coordinates
   - the true (linear) Euclidean distance between probe and reference - only
   whether the *squared* distance clears the *squared* threshold is revealed

3. **Fixed-Point Field-Safety**: Coordinates are bounded (`MaxCoordAbs`) so the
maximum possible accumulated squared distance is many orders of magnitude below
the scalar field modulus, ruling out modular wraparound as a source of false
positives or false negatives in the comparison.

4. **Reference Provenance (assumed, not proven in-circuit)**: The public
reference embedding is expected to have been extracted from a digitally signed
e-ID credential and verified by the caller *before* it reaches this circuit. The
circuit does not check any signature over the reference embedding itself - that
trust boundary lives entirely outside this package. This rules out a party
fabricating an arbitrary reference to forge a match, but does **not** by itself
rule out an adaptive-query attack in which a verifier who controls proof
attempts reuses the same genuine reference across many proofs with different
thresholds, using pass/fail as a 1-bit oracle on the probe embedding. Callers
should rate-limit verification attempts and treat the reference as fixed per
identity.

5. **Normalization & Range Checks**: The comparison only has meaningful
"closeness" semantics when both embeddings are L2-normalized unit vectors. This
is checked in Go (`WitnessInput.Validate`) before witness generation, not inside
the R1CS circuit itself, since the circuit has no model-specific notion of what
"normalized" means for a caller's embeddings. A non-normalized embedding causes
proof/verification-request construction to fail with a validation error rather
than producing a proof with silently wrong semantics.

6. **Liveness & Replay**: Out of scope for this circuit.

## Summary of the public and private inputs

Private inputs (known only to the holder/prover):

- Probe face embedding (fixed-point quantized), one coordinate per embedding
dimension
  - Proves the holder controls a face embedding close enough to the public
  reference to be considered a match, without revealing the embedding itself

Public inputs (used by the verifier as input):

- Reference face embedding (fixed-point quantized)
  - Expected to be sourced from a verified, digitally signed e-ID credential;
  see "Reference Provenance" above
- Squared distance threshold
  - The maximum allowed squared Euclidean distance between probe and reference
  for a match; derived from a verifier-chosen linear threshold

Out of scope of this circuit:

- Verifying the reference embedding's provenance/signature (must be done by the
caller before invoking this circuit)
- Enforcing L2-normalization of embeddings inside the circuit (done in Go, not
in R1CS - see "Normalization & Range Checks" above)
- Liveness detection / anti-spoofing (e.g. distinguishing a live face from a
photo or replayed embedding)
- Replay protection / session binding (nonce or verifier-provided challenge
folded into the proof)
- Rate-limiting of verification attempts (mitigates the adaptive
reference/threshold oracle risk noted above)
