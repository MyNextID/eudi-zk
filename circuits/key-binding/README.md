# Circuit: Key binding verification

Version: 1

## Overview

This circuit verifies whether a holder can cryptographically prove it controls
a Verifiable Credential (VC)

### Steps

- Verify kid exists in JWT header at claimed position
- Decode hex kid to bytes
- Hash the public key
- Verify hash matches kid

## Artefacts

- Verifiable Credential (VC) signed using JWT or JWS. JWT/JWS consists of three
main parts: protected header, payload, signature
  - Verifiable Credential contains a cnf claim in the protected header
  - Value of the cnf claim is the public key identifier: SHA256 of the public key
- Signer's:
  - secret key: to sign the challenge
  - public key: to verify the challenge and to verify the public key is in the VC
  - signature of the challenge (proof of possession)
- Verifier-defined challenge

## Private inputs

These artefacts are known only to the proofer and are not revealed to the
verifier:

- protected JWT/JWS header (we assume all non-PII signature metadata is in the protected header and not in the payload)
- signer's public key
- proof of possession (signature of the signed challenge)

## Public inputs

These artefacts are known to both the proofer and the verifier and the verifier
is using them as input to the verification function

- challenge

## ZK Circuit Verification Functions

- verify that the public key validates the signature of the challenge
  - compute SHA256 hash of the challenge
  - verify the signature using holder's public key
- verify that the holder's public key is in the protected header
  - decode the header
  - encode or decode the public key hash
  - perform a byte comparison
