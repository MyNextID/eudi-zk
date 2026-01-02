# Temporal Validation Circuits

Version: 1

## Overview

These circuits provide zero-knowledge proofs for temporal validity constraints
in verifiable credentials and certificates. They enable privacy-preserving
verification of time-based claims (such as age requirements) without revealing
the actual dates or credential contents.

## What We Prove

The circuits prove that a date claim within a credential satisfies a temporal
constraint relative to a threshold date, without revealing:

- The actual date value
- The full credential payload
- The position of the date within the credential
- Any other personal information in the credential

## Use Cases

### Over XX (Age Verification)

The [OverXX](./overXX.go) circuit proves that a person meets an age threshold
(e.g., over 18, over 21) based on their birthdate in a credential, without
disclosing the exact birthdate or any other personal information.

What it proves?

> I possess a valid credential containing a birthdate claim that proves I was
born before the threshold date (PUBLIC), making me old enough to meet the age
requirement.

**Privacy guarantees:**

- Actual birthdate remains secret
- Credential contents remain secret  
- Position of the birthdate within the credential remains secret
- Only reveals: "Yes, I meet the age requirement"

**Public inputs (visible to verifier):**

- `ThresholdDate`: The age threshold in YYYY-MM-DD format (e.g., "2006-01-01" for over-18 verification in 2024)
- `Claim`: The name of the date field to verify (e.g., "birthdate", "date_of_birth", "birth_date")

Note: credential type should also be referenced to ensure the correctness of the
claim meaning/vocabulary/namespace.

**Private inputs (secret to prover):**

- `Payload`: The base64url-encoded credential payload
- Internal positions and extracted data (automatically computed)

### Technical Approach

The circuit performs these verification steps:

1. **Subset verification**: Proves that a base64url-encoded date claim is
embedded within the base64url-encoded credential payload at a specific position
(using padding-aware comparison)

2. **Claim name validation**: Verifies that the specified claim name (e.g.,
"birthdate") appears within the date claim at a specific position, ensuring the
correct field is being validated

3. **Base64 decoding**: Decodes the base64url-encoded date claim to extract the
JSON data containing the date

4. **Date extraction**: Extracts the actual date string (YYYY-MM-DD format) from
within the decoded JSON at a specific position

5. **Lexicographical comparison**: Performs lexicographical comparison to verify
the birthdate is before the threshold date (proving age eligibility)

All positions and intermediate values remain private, providing strong privacy
guarantees.

### Verification Mechanism: Lexicographical Comparison

The circuit employs lexicographical string comparison as its core verification
mechanism. This approach works because of a crucial property of the ISO 8601
date format (YYYY-MM-DD): for any two dates d_1 and d_2, we have d_1 < d_2
chronologically if and only if d_1 < d_2 lexicographically when both are
represented as strings in this format.

**Why this works:**

The year-first ordering with fixed-width zero-padded fields ensures that string
comparison naturally mirrors temporal ordering:

- "1990-01-01" < "2006-01-01" (lexicographically and chronologically)
- "2005-12-31" < "2006-01-01" (lexicographically and chronologically)

**Verification logic:**

The verifier specifies a minimum birthdate threshold `d_threshold`. The circuit
proves that the claimant's birthdate `d_claim` satisfies:

```text
d_claim < d_threshold (lexicographically) -> person is old enough
```

For example, if `d_threshold = "2006-01-01"` (for over-18 verification in 2024), then:

- `d_claim = "1990-05-15"` → "1990-05-15" < "2006-01-01" → **VALID** (person is over 18)
- `d_claim = "2010-03-20"` → "2010-03-20" > "2006-01-01" → **INVALID** (person is under 18)

**Generalization:**

This comparison technique generalizes naturally: any claim values that can be
represented in a lexicographically-ordered format may be compared using the same
fundamental mechanism, making the approach broadly applicable beyond age
verification alone.

## Supported Date and Time Formats

### ISO 8601 (Supported)

- Format: `YYYY-MM-DD`
- Example: "2006-01-01"
- Lexicographical comparison: Supported
- Use case: Birthdate verification, date-based claims in W3C Verifiable
Credentials, SD-JWT VCs

JWS signature and JSON payload formats are the primary formats supported by the
current circuit implementation.

### GeneralizedTime (X.509 Certificates)

- Format: `YYYYMMDDHHMMSSZ`
- Example: "20240315120000Z"
- Lexicographical comparison: Supported (strings compare correctly with other
GeneralizedTime strings)
- Use case: X.509 certificate validity periods (dates in 2050 and beyond)

**Note:** When using GeneralizedTime, the reference threshold date must also be
in GeneralizedTime format. You cannot meaningfully compare a GeneralizedTime
string against a UTCTime string lexicographically.

### UTCTime (X.509 Certificates) - Not Currently Supported

- Format: `YYMMDDHHMMSSZ`
- Example: "240315120000Z" (March 15, 2024)
- Lexicographical comparison: Not supported directly

**Issue**: UTCTime does not support lexicographical comparison even within its
own format due to its year encoding scheme. The two-digit year YY is interpreted
with a pivot rule:

- 50-99 represents 1950-1999
- 00-49 represents 2000-2049

This means "50" (1950) follows "49" (2049) lexicographically despite
representing an earlier date, breaking the fundamental requirement for
lexicographical comparison.

**Solution:** To compare UTCTime values, the correct century prefix must be
added first—transforming "49..." to "2049..." and "50..." to "1950..."—thereby
converting to GeneralizedTime-like format before comparison.

**Status:** Extension for UTCTime representation has not been implemented.

### Unix Timestamp - Not Currently Supported

- Format: Integer seconds since Unix epoch (January 1, 1970, 00:00:00 UTC)
- Example: 1710504000 (March 15, 2024)
- Numeric comparison: Supported (when parsed as integers)
- Lexicographical comparison: Problematic when transmitted as strings

**Issue:** When Unix timestamps are transmitted as strings (as in JSON Web Tokens), lexicographical comparison fails. Consider:

- "999999999" (Sep 9, 2001) > "1000000000" (Sep 9, 2001 + 1 second) lexicographically
- This is because "999999999" has 9 digits while "1000000000" has 10 digits

**Solution:**

1. Parse strings into integers before comparison (proper numeric ordering)
2. Normalize string representation with fixed-width zero-padding: "0999999999" vs "1000000000"

The applicability of lexicographical comparison depends not merely on the
semantics of the data format, but critically on its syntactic representation as
a string.

**Status:** Extension for Unix timestamp representation has not been
implemented.

## Other use cases

The lexicographical comparison technique can be extended to:

- **Credential validity periods:** Prove a credential is currently valid
- **License expiration:** Prove a license hasn't expired
- **Sequential ordering:** Prove events occurred in a specific order
- **Threshold comparisons:** Prove any numeric or temporal value meets a threshold

## References

- [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601): Date and time format standard
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html): JSON Web Token (JWT)
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html): JSON Web Signature (JWS)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/): Selective Disclosure for JWTs data model
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html): Mobile driving licence (mDL)
- [X.509](https://en.wikipedia.org/wiki/X.509)
