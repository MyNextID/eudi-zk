# Key Binding JWT profile for Zero Knowledge Proofs

Version: draft

In this document we define a [Key Binding JWT](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding-jwt) verifiable presentation profile for Zero Knowledge Proofs.

## Overview

Minimal information that MUST be provided within the presentation:

ZK circuit information:

- `zkid`: REQUIRED. ZK Circuit identifier
- `zkpin`: OPTIONAL. Public ZK circuit inputs, if available.
- `zkparams`: OPTIONAL. ZK Circuit-specific parameters, e.g., verification key, if applicable
- `zkp`: REQUIRED. ZK proof.

Public ZK circuit inputs MUST contain at least the following elements

- `iat`: REQUIRED. The value of this claim MUST be the time at which the Key Binding JWT was issued using the syntax defined in [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
- `aud`: REQUIRED. The value MUST be a single string that identifies the intended receiver of the Key Binding JWT.
- `nonce`: REQUIRED. Ensures the freshness of the signature or its binding to the given transaction. The value type of this claim MUST be a string.

## Data model

JOSE protected header MUST contain the following elements

- typ: value MUST be `zkp+jwt`
- alg: value MUST be `none`

Payload elements

## Examples
