# Circuit: Signature Verification

Version: 1

## Overview

CircuitJWS implements a zero-knowledge proof circuit for validating JWS (JSON
Web Signature) signatures with X.509 certificate chain verification.

What the circuit proves? The prover demonstrates knowledge of certain
cryptographic relationships without revealing the underlying secrets.
Specifically, the circuit establishes three facts:

- Signature validity - A JWS signature correctly authenticates a given payload
under the standard JWS verification algorithm.
- Public key certificate validity - The signature was created using a private key $sk$ whose
corresponding public key $pk$ appears within an X.509 certificate.
- Certificate authority - Said X.509 certificate bears a valid signature from a
Qualified Trust Service Provider (QTSP), establishing the certificate's
authenticity through the standard chain-of-trust mechanism.

**Private inputs** (known to the prover, hidden from the verifier):

- The JWS protected header, containing metadata such as algorithm identifiers and key identifiers;
- The signer's public key $pk$ that produced the JWS signature;
- The complete X.509 certificate embedding $pk$ and containing the signer's identity information.

**Public inputs** (known to both prover and verifier):

- The JWS payload—the actual data bearing the signature;

- The QTSP's public key, serving as the trust anchor for certificate verification.

Application: This construction enables a prover to establish that "a document
carries a valid signature from an entity whose public key certificate was issued
by a trusted QTSP," while simultaneously concealing the specific identity of the
signing entity and the particulars of their certificate. This proves
authenticity without sacrificing anonymity.

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
