# Circuit: verify-jws-cert

Version: 1

## Overview

The `verify-jws-cert` circuit implements a zero-knowledge proof system for
validating JWS (JSON Web Signature) signatures with X.509 certificate chain
verification, following RFC 7515 (JWS) and RFC 5280 (X.509).

### What Does This Circuit Prove?

The prover demonstrates knowledge of certain cryptographic relationships without
revealing the underlying secrets. Specifically, the circuit establishes three
facts:

1. **JWS Signature Validity** - A JWS signature correctly authenticates a given
payload under the ES256 (ECDSA with P-256 and SHA-256) signature algorithm. The
circuit verifies:

```text
ECDSA_Verify(SignerPubKey, SHA256(Protected || "." || Payload), JWS_Signature) = valid
```

2. **Public Key Binding** - The signature was created using a private key whose
corresponding public key appears within an X.509 certificate. The circuit proves
that the signer's public key extracted from the certificate matches the key used
to create the JWS signature.

3. **Certificate Authority Validation** - The X.509 certificate containing the
signer's public key bears a valid ECDSA signature from a Qualified Trust Service
Provider (QTSP), establishing authenticity through the standard chain-of-trust
mechanism:

```text
ECDSA_Verify(QTSP_PubKey, SHA256(CertificateTBS), Certificate_Signature) = valid
```

### Zero-Knowledge Properties

**Private Inputs** (known to the prover, hidden from the verifier):

- JWS protected header (base64url-encoded) - contains signature metadata like algorithm, key ID, etc.
- Signer's ECDSA public key (X, Y coordinates on secp256r1/P-256 curve)
- JWS signature components (R, S values)
- Complete X.509 certificate TBS (To Be Signed) data containing the signer's identity
- X.509 certificate signature components (R, S values)
- SHA-256 hash of the JWS signing input (Protected.Payload)

**Public Inputs** (known to both prover and verifier):

- JWS payload (base64url-encoded) - the actual signed data
- QTSP's ECDSA public key (X, Y coordinates) - the trust anchor for certificate verification

### Use Case

This construction enables a prover to establish that "a document carries a valid
digital signature from an entity whose public key certificate was issued by a
trusted QTSP," while simultaneously concealing:

- The specific identity of the signing entity
- The complete contents of their certificate
- Metadata about the signature algorithm and keys

This proves authenticity and comformity without sacrificing anonymity*

## ZK Circuit Verification Functions

The circuit performs three main verification steps:

### 1. Verify JWS Signature (RFC 7515)

Purpose: Prove that the JWS signature is valid for the given payload.

Algorithm:

1. Construct JWS signing input: Protected || "." || Payload
2. Compute SHA-256 digest of signing input
3. Verify ECDSA signature using signer's public key:
  `ECDSA_Verify(SignerPubKey, Hash, (JWSSigR, JWSSigS)) = true`

Constraints: Uses ECDSA verification gadget over secp256r1 (P-256) curve with
emulated field arithmetic.

### 2. Verify X.509 Certificate Signature (RFC 5280)

Purposes: Prove that the signer's certificate was validly signed by the QTSP.

Algorithm:

1. Extract TBS (To Be Signed) portion of certificate
2. Compute SHA-256 digest of TBS data
3. Verify ECDSA signature using QTSP's public key:
  `ECDSA_Verify(QTSPPubKey, SHA256(CertTBS), (CertSigR, CertSigS)) = true`

Constraints: Uses ECDSA verification over secp256r1 (P-256) curve.

### 3. Verify Public Key Binding

Purpose: Prove that the public key used to verify the JWS signature is embedded
in the X.509 certificate validated in step 2.

Algorithm:

1. Extract signer's public key from certificate TBS data
2. Verify extracted key matches the key used in JWS verification:
  `ExtractedPubKey == SignerPubKey`

Constraints: Parses ASN.1 DER-encoded certificate structure to locate and extract the subject public key field.

## Security Considerations

### Cryptographic Assumptions

- **ECDSA Security**: Relies on the hardness of the Elliptic Curve Discrete
Logarithm Problem (ECDLP) on the secp256r1 (NIST P-256) curve
- **Hash Function Security**: Assumes SHA-256 is collision-resistant and
provides second-preimage resistance
- **Zero-Knowledge Property**: The proof reveals nothing beyond the validity of
the three proven statements

### Trust Model

- **QTSP Trust**: The verifier must trust the QTSP whose public key is provided
as a public input
- **Certificate Chain**: The QTSP's own certificate chain is verified outside
the ZK circuit
- **Revocation**: Certificate revocation status is NOT checked within the
circuit

### Implementation Notes

- All field arithmetic for ECDSA is emulated using gnark's `emulated` package
- Padding is used for variable-length inputs to create fixed-size circuit constraints
- The SHA-256 hash is pre-computed and provided as input to reduce circuit complexity

## Use Case: Anonymous Qualified Electronic Signature

Scenario: A citizen needs to prove they can create a qualified electronic
signature from a government-approved QTSP without revealing their identity.

Setup:

1. Citizen obtains X.509 certificate from QTSP (contains their identity)
2. Citizen signs a document using their certificate's private key (creates JWS)
3. QTSP's public key is publicly known and trusted

Proof Generation:

1. Citizen creates ZK proof showing:
   - Their JWS signature on the document is valid
   - Their certificate was issued by the trusted QTSP
   - The key used for the signature matches the certificate
2. Citizen provides only the document (payload) and QTSP public key publicly

Verification:

1. Verifier checks the ZK proof against the document and trusted QTSP key
2. Verifier learns: "This document has a valid qualified signature"
3. Verifier does NOT learn: Who signed it or any certificate details

Result: Anonymous yet trustworthy digital signature, suitable for privacy-preserving e-government applications.

## References

- [RFC 7515](https://tools.ietf.org/html/rfc7515): JSON Web Signature (JWS)
- [RFC 5280](https://tools.ietf.org/html/rfc5280): X.509 Public Key Infrastructure Certificate
- [RFC 5480](https://tools.ietf.org/html/rfc5480): Elliptic Curve Cryptography Subject Public Key Information
- FIPS 186-4: Digital Signature Standard (DSS) - ECDSA specification
- eIDAS Regulation: EU regulation for electronic identification and trust services
