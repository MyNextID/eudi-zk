# Face Match Circuit

Version: 1

## What We Prove

The verification establishes the following properties in a single proof:

1. **Bounded Proximity Match**: The holder possesses a private ("reference")
face embedding whose squared Euclidean distance to a public ("probe") face
embedding is at or under a public squared distance threshold. Both embeddings
are represented as fixed-point (scaled integer) coordinates so the entire
comparison reduces to subtraction, multiplication, and a single
range-check-based inequality assertion inside the circuit.
2. **Privacy Preservation**: All of the above is proven without revealing: - the
holder's reference embedding coordinates - the true (linear) Euclidean distance
between reference and probe - only whether the *squared* distance clears the
*squared* threshold is revealed
3. **Fixed-Point Field-Safety**: Coordinates are bounded (`MaxCoordAbs`) so the
maximum possible accumulated squared distance is many orders of magnitude below
the scalar field modulus, ruling out modular wraparound as a source of false
positives or false negatives in the comparison.
4. **Reference Provenance**: The private reference embedding is assumed to have
been extracted from a digitally signed e-ID credential - the same trust role the
certificate/VC-binding steps play in the main EUDI VC circuit. **This circuit
does not itself check any signature over the reference embedding.** `Define()`
only computes squared distance and compares it to the threshold; nothing here
binds `ReferenceEmbedding` to a credential. Because it is a private witness, the
prover fully controls its value, so on its own this circuit cannot distinguish a
genuine credentialed embedding from one the prover simply made up (e.g. copying
the public probe vector to trivially pass). This circuit is meant to compose
with a separate circuit that proves the prover holds a validly-signed credential
containing that exact embedding (analogous to Certificate Ownership / Key
Possession in the main EUDI VC circuit); the two proofs must be chained or
otherwise bound together by the caller for the provenance assumption to hold.
The probe embedding carries no such assumption - it is expected to come from an
unattested source at the point of verification (e.g. a live face-scanning
device) and is not required to trace back to any signed credential.
5. **Normalization & Range Checks**: The comparison only has meaningful
"closeness" semantics when both embeddings are L2-normalized unit vectors. This
is checked in Go (`WitnessInput.Validate`) before witness generation, not inside
the circuit itself, since the circuit has no model-specific notion of what
"normalized" means for a caller's embeddings. A non-normalized embedding causes
proof/verification-request construction to fail with a validation error rather
than producing a proof with silently wrong semantics.
6. **Liveness, Replay & Adaptive Queries**: Out of scope for this circuit. It
only asserts "I know a reference embedding close to this probe." It does not
bind the proof to a session, nonce, timestamp, or liveness check. A captured
proof (or a captured quantized reference embedding) can be replayed indefinitely
unless the calling protocol folds in an external challenge and a separate
liveness-detection step. Because the probe vector is public and carries no
provenance assumption (see "Reference Provenance" above - it may simply be
whatever a face-scanning device produced for this session), a verifier who
controls repeated proof attempts could in principle vary the probe and/or
threshold across queries and use pass/fail as a 1-bit oracle to narrow down the
private reference embedding. Callers should rate-limit verification attempts and
treat this as a protocol-level concern this circuit does not address.

## Summary of the public and private inputs

Private inputs (known only to the holder/prover):

- Reference face embedding (fixed-point quantized), one coordinate per
embedding dimension
  - Proves the holder controls a face embedding close enough to the public
  probe to be considered a match, without revealing the embedding itself
  - Assumed (not proven by this circuit) to be extracted from a digitally
  signed e-ID credential; see "Reference Provenance" above
Public inputs (used by the verifier as input):
- Probe face embedding (fixed-point quantized)
  - Carries no provenance assumption - e.g. it may come from an unattested
  face-scanning device at the point of verification
- Squared distance threshold
  - The maximum allowed squared Euclidean distance between reference and
  probe for a match; derived from a verifier-chosen linear threshold
Out of scope of this circuit:
- Verifying the reference embedding's provenance/signature (proven by a
separate, composing circuit - see "Reference Provenance" above - and must be
chained or otherwise bound to this proof by the caller)
- Enforcing L2-normalization of embeddings inside the circuit (done in Go,
not in R1CS - see "Normalization & Range Checks" above)
- Liveness detection / anti-spoofing (e.g. distinguishing a live face from a
photo or replayed embedding)
- Replay protection / session binding (nonce or verifier-provided challenge
folded into the proof)
- Rate-limiting of verification attempts (mitigates the adaptive
probe/threshold oracle risk noted above)
