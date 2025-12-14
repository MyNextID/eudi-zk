# Zero-Knowledge Proof for EUDI Wallet Credential Presentation

## Overview

This zero-knowledge proof system enables privacy-preserving credential
verification for EU Digital Identity (EUDI) wallets and other digital identity
systems. The system proves that a holder possesses a valid verifiable credential
issued by a trusted authority, can authenticate themselves via
challenge-response, and holds a certificate signed by a recognized Certificate
Authority — all without revealing the actual credential, certificate, or
cryptographic keys.

## What We Prove

The verification establishes five critical security properties in a single
proof:

1. **Certificate Ownership & Authenticity**: The holder possesses an X.509
certificate containing a specific public key, and this certificate is validly
signed by a trusted Certificate Authority (CA/QTSP)

2. **Key Possession**: The holder controls the private key corresponding to the
public key embedded in their certificate, proven by signing a verifier-provided
challenge

3. **Credential Validity**: The holder possesses a verifiable credential (VC)
issued by a legitimate issuer, signed using JSON Web Signature (JWS)

4. **Identity Binding**: The credential is bound to the certificate holder
through a confirmation claim (cnf) that references the holders's public key

5. **Privacy Preservation**: All of the above is proven without revealing: the
holder's certificate, the holder's public key, the challenge signature (from
which for elliptic curves we can derive the public key), the credential's
signature protected header that contains all the credential metadata.

## Technical Implementation

### Step-by-Step Verification Process

#### Step 1-2: Certificate Structure Navigation & Position Verification

The circuit navigates through the X.509 DER-encoded certificate structure in
strict sequential order, verifying each field tag to ensure we're extracting the
**holder's public key** (not the issuer's or any other embedded key). This
proves structural integrity and prevents key substitution attacks.

**Security Achievement**: Cryptographically proves the extracted public key came
*from the SubjectPublicKeyInfo field (the 7th field in the TBSCertificate
*structure), making it impossible for a malicious prover to substitute another
*key.

#### Step 3-4: Public Key Extraction & Validation

The circuit extracts the 65-byte uncompressed EC public key (P-256 curve) from
the certificate's BIT STRING and verifies it matches the claimed public key
coordinates (X, Y). This includes validating the DER encoding structure (tag
0x03, length 0x42, unused bits 0x00, format 0x04).

**Security Achievement**: Ensures the public key used for subsequent
*verifications actually comes from the certificate, establishing a cryptographic
*chain of trust.

#### Step 5: Challenge-Response Authentication

The circuit verifies an ECDSA signature over a verifier-provided 32-byte
challenge using the holder's public key. The challenge is hashed with SHA-256,
and the signature (R, S components) is verified against the secp256r1 curve
parameters.

**Security Achievement**: Proves the holder controls the private key
corresponding to the certificate's public key, establishing **proof of
possession** without revealing the private or the public key or the signature
value itself. Note: from the signature we can derive the public key.

#### Step 6: Certificate Authority Signature Verification

The circuit verifies the CA's ECDSA signature over the TBSCertificate
(To-Be-Signed certificate portion). The CA's public key is provided as a public
input, allowing verifiers to specify which CAs they trust.

**Security Achievement**: Proves the certificate was issued by a trusted CA
*without revealing the certificate contents, enabling trust anchor verification
*while maintaining privacy.

#### Step 7: Verifiable Credential (JWS) Signature Verification

The circuit verifies the issuer's ECDSA signature over the JWS signing input
(base64url-encoded header + "." + base64url-encoded payload). The protected
header contains the holder's key identifier (cnf) that should match the hash of
the holder's public key.

Protected header is a private input, whereas the payload is the public input.

**Security Achievement**: Proves the credential was issued by a legitimate
*issuer and binds it to the holder's certificate through the `cnf` claim.

#### Step 8: Key Binding Verification (Pending Implementation)

*Note: The final verification—confirming that the cnf in the JWS header matches
*the SHA-256 hash of the holder's public key—is still in progress in the current
*implementation. This step is critical for completing the cryptographic binding
*between the certificate and credential.*

### Roadmap

- Add CRL verification
- Selective disclosure of claims

## Performance Analysis

The proof generation completed with these metrics:

```bash
Circuit Complexity:  906,670 constraints
Setup Time:         2m 13.6s (one-time cost)
Witness Creation:   830.8µs
Proof Generation:   3.9s
Proof Verification: 2.2ms
```

### Real-Time Use Implications

**One-Time Setup (2m 13s)**

- Performed once per circuit configuration
- Can be pre-computed and reused across all proofs
- In production, this would be done during system initialization or deployment
- End users never experience this delay

**Proof Generation (3.9 seconds)**

- This is the time a wallet holder needs to generate a proof when presenting credentials
- Acceptable for high-security scenarios (border control, financial services)
- May be noticeable in retail/casual authentication scenarios
- Could be optimized through:
  - Hardware acceleration (specialized proof generation chips)
  - Cloud-based proving services (with privacy considerations)
  - Circuit optimization to reduce constraint count

**Proof Verification (2.2 milliseconds)**

- Extremely fast, enabling real-time verification
- Suitable for any application, including high-volume scenarios
- Verifiers experience no noticeable delay
- Scales efficiently: one verifier can check thousands of proofs per second

**Witness Creation (830µs)**

- Negligible overhead in preparing the proof inputs
- Not a performance concern

### Security-Privacy Trade-off Achievement

This proof system achieves **maximum privacy** while maintaining **cryptographic security**:

- **Zero Knowledge**: The verifier learns ONLY that all checks passed, nothing about the actual data
- **Selective Disclosure**: Can be extended to prove specific claims (e.g., "over 18") without revealing exact age
- **Trust Anchor Flexibility**: Verifier specifies trusted CAs/issuers as public inputs
- **Replay Protection**: Each challenge is unique, preventing proof reuse
- **Cryptographic Strength**: Based on ECDSA security over NIST P-256 curve

### Circuit Complexity Context

This circuit is for discussion and educational purposes only. For production
use, more optimized frameworks, such as Longfellow-ZK are being used.

## Implications for EUDI and eIDAS

Using ZKP, we can, establish digital wallet infrastructure on top of the
existing QTSP IT and trust infrastructure as QTSPs can:

- issue advanced or qualified certificates to Legal Entities (issuers or holders)
- issue advanced or qualified certificates to Natural Persons (holders)

Without changing the underlying cryptography, we can achieve the desired level
of unlinkability/pseudonymity/anonymity, depending on the use case needs,
without jeopardising the security. This circuit works with keys managed in HSMs
and doesn't require any changes to the existing e-signing or e-sealing
infrastructure.

## Conclusion

This zero-knowledge proof system successfully demonstrates a privacy-preserving
EUDI wallet implementation that balances strong cryptographic security with
practical usability. While the 4-second proof generation time may limit some
real-time applications, it is entirely acceptable for high-security credential
verification scenarios where privacy is paramount. The sub-3-millisecond
verification time ensures verifiers experience no performance degradation,
making the system highly scalable for deployment.

## Note on the credential formats

ZKPs are much more efficient with byte-encoded payloads without additional
hex/base64 encodings. E.g., processing DER encoded VCs is much more efficient
than JWT/JWS based signatures. In the case of mDL/mDoc, CBOR encoding is
sufficient, as there's no need to apply the mDoc salted-hash table selective disclosure approach as it can be achieved using the ZKP itself.
