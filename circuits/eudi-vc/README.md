# EUDI VC Circuits

Version: 1

## What We Prove

The verification establishes six critical security properties in a single
proof:

1. **Certificate Ownership & Authenticity**: The holder possesses an X.509
certificate containing a specific public key, and this certificate is validly
signed by a trusted Certificate Authority (CA/QTSP)

2. **Key Possession**: The holder controls the private key corresponding to the
public key embedded in their certificate, proven by signing a verifier-provided
challenge

3. **Credential Validity**: The holder possesses a verifiable credential (VC)
issued by a legitimate issuer. We showcase a VC (payload can be W3C VCDM, SD-JWT
VC, ID Token or any other JSON or JSON-LD) signed using JSON Web Signature (JWS).

Note: JSON-LD `@context` can be present, but it is not processed within the
circuit when signature format is JWS. JSON-LD can be, however, processed before
passing the payload to the ZK circuit, if digital signature format is W3C
Verifiable Credential Data Integrity. Data Integrity signatures are out of scope
of this work.

4. **Identity Binding**: The credential is bound to the certificate holder
through a key identifier (kid) that references the holders's public key. The
reference is made in the confirmation claim (`cnf`) that we put in the protected
JWS header. The `kid` member of the `cnf` claim contains hex encoded SHA256
digest of the public key (for the elliptic curves, uncompressed public key).

5. **Privacy Preservation**: All of the above is proven without revealing:

- the holder's public key certificate
- the holder's public key
- the holder's signature of the verifier-provided challenge (from
which for elliptic curves we can derive the public key)
- the VC signature and the protected header that contain all the signature metadata

6. **CRL**: Circuit for basic CRL verification has been added; not integrated
into the main circuit, yet; it's slightly inefficient for the moment

## Summary of the public and private inputs

Private inputs (known only to the holder/prover):

- Holder's public key certificate
  - contains holder's public key
- JWS protected header
  - contains digest of the holder's public key (confirmation claim)
- JWS signature value
  - Validates the VC
- Signature of the challenge created by the holder with it's private key
  - Proves the holder owns the private key that has a public key to which the VC
  has been cryptographically bound

Public inputs (used by the verifier as input):

- Random verifier-defined challenge
- Public key of the Certificate Authority/QTSP signing the holder's public key
certificate: enables to validate the holder's public key certificate
- Public key of the VC issuer: enables to validate the VC signature
- VC payload (JWS payload)

Out of scope of this circuit:

- Selective disclosure of the payload claims (trivial to implement)
