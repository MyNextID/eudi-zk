# Circuit: Key binding verification

Version: 1

## Overview

This circuit verifies whether a holder can cryptographically prove it controls
a Verifiable Credential (VC)

### Steps

- Verify `cnf` exists in JWS header at claimed position - base64 encoded comparison
- Decode the base64 encoded cnf
- Decode the hex encoded public key digest
- Compute the digest of the provided public key (private input)
- Verify that the digests of the provided and extracted keys match

## Artefacts

- Verifiable Credential (VC) signed using JWS. The signature consists of three
main parts: protected header, payload, signature
  - Verifiable Credential contains a `cnf` claim in the protected header; We put
  all the signature metadata in the protected header to separate the signature
  and holder binding, and user info processing.
  - The confirmation `cnf` claim must contain the `kid` member identifying the
  public key as SHA256 digest of uncompressed public key (for elliptic curve keys)
- Signer's:
  - secret key: to sign the challenge
  - public key: to verify the challenge and to verify the public key is in the VC
  - signature of the challenge (proof of possession)
- Verifier-defined challenge

## Private inputs

These artefacts are known only to the proofer and are not revealed to the
verifier:

- protected JWS header (we assume all non-PII signature metadata is in the protected header and not in the payload)
- signer's public key
- proof of possession (signature of the signed challenge)

## Public inputs

These artefacts are known to both the proofer and the verifier and the verifier
is using them as input to the verification function

- verifier-defined challenge

## ZK Circuit Verification Functions

- Verify that tha base64url encoded `cnf` claim is part of the protected header
- Decode the `cnf` claim
- Extract the public key digest from the `kid` member of the `cnf` claim
- Decode the public key digest
- Compute the public key digest (SHA256) of the provided public key
- Compare the public key digest from the protected header with the computed digest
