# Circuit: Signature Verification

Version: 1

## Overview

CircuitJWS implements a zero-knowledge proof circuit for validating JWS (JSON
Web Signature) signatures with X.509 certificate chain verification.

Zero-Knowledge Properties:
The circuit PROVES the following statements without revealing sensitive data:

1. A JWS signature is cryptographically valid for a given payload
2. The signature was created using a private key whose public key is embedded in an X.509 certificate
3. That X.509 certificate is validly signed by a Qualified Trust Service Provider (QTSP)

What remains PRIVATE (hidden from verifiers):

- JWS protected header (contains metadata like algorithm, key ID)
- Signer's public key (the actual key used to create the JWS signature)
- Complete X.509 certificate of the signer that contains signer's identity information

What is PUBLIC (visible to verifiers):

- JWS Payload (the actual data being signed)
- QTSP's public key (the trusted authority's public key used to verify the certificate chain)

Use Case Example:

This allows proving "a document has been signed with a valid signature from
using a secret key whose public key has a public key certificate issued by a
QTSP" without revealing which specific entity signed it or their certificate
details.

## Artefacts

- Verifiable Credential (VC) signed using JWT or JWS. JWT/JWS consists of three main parts
  - protected header: contains signature metadata
  - payload: content
  - signature: digital signature
- Signer's:
  - secret key: to sign the VC
  - public key: to verify the VC signature
  - public key certificate (X.509): to verify that the key has been recognised by a Certificate Authority (e.g., QTSP)
- Certificate Issuer's:
  - secret key: to sign the signer's public key certificate
  - public key: to verify the signature of the signer's public key certificate
  - public key certificate (X.509): to verify the trust chain

## Private inputs

These artefacts are known only to the proofer and are not revealed to the
verifier:

- protected JWT/JWS header (we assume all non-PII signature metadata is in the protected header and not in the payload)
- signer's public key
- signer's public key certificate

## Public inputs

These artefacts are known to both the proofer and the verifier and the verifier
is using them as input to the verification function

- VC payload
- Certificate issuer's public key. Note: Issuer's certificate (chain) is verified outside of the ZK circuit

## ZK Circuit Verification Functions

- verify the VC signature (JWT/JWS)
  - construct the JWT_message = base64url(header) || '.' || base64url(payload)
  - compute the digest
  - validate the signature
- verify that the signer's public key is in the x509 DER cert
- verify that the CA's public key verifies the signature of the signer's x509 certificate
