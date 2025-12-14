# ZK Circuits for eIDAS and EUDI

## Overview

This repository implements zero-knowledge proof circuits for the eIDAS
(Electronic Identification, Authentication and Trust Services) and EUDI
(European Digital Identity) ecosystems using
[Gnark](https://docs.gnark.consensys.io/), a Go-based zk-SNARKs framework.

**Why Gnark?** We chose Gnark for rapid prototyping due to its
developer-friendly API and readable codebase. These reference implementations
demonstrate core ZKP capabilities but are not production-optimized.

**Production Implementation:** Our future system is being built using
[Longfellow-ZK](https://github.com/google/longfellow-zk), which offers superior
performance for:

- Server-side proof generation with HSM-protected keys
- Resource-constrained devices using standard cryptographic keys

All the circuits presented here are framework-agnostic and can be implemented in
alternative ZKP systems like
[Longfellow-ZK](https://github.com/google/longfellow-zk/) or
[zkID/OpenAC](https://pse.dev/projects/zk-id) or other ZK frameworks.

## Motivation

The main motivations for this work are:

**Complexity of credential management with salt-hash table-based selective disclosure.**
Achieving even the simplest form of unlinkability requires one-time credentials
where batches must be managed by both the issuer and the wallet. This creates
high operational complexity and tight coupling between issuers and wallets.

**Demonstrating infrastructure reusability.**
We aim to show that existing e-signing and e-sealing infrastructure can be
reused as-is to introduce efficient wallet systems, requiring only the addition
of ZKP circuits.

With ZK circuits we can achieve different levels of
linkability/pseudonymity/anonymity as described in
[PII linkability, pseudonymity, and anonymity](./docs/unlinkability.md).

## Getting Started

Start exploring the circuits:

- **All circuits:** [circuits/](./circuits/README.md)
- **Simple circuits:** [circuits/compare-bytes/](./circuits/compare-bytes/README.md)
- **EUDI/eIDAS circuits:** [circuits/eudi-vc/](./circuits/eudi-vc/README.md)

## Core Circuits

We've developed two fundamental circuit families relevant for verification in
the eIDAS/EUDI context:

### 1. eIDAS Signature Verification

Location: [circuits/signature-verification/](./circuits/verify-eidas-signature)

Proves that a signed payload is valid without revealing the signature, public
key, or the public key certificate, while proving that the certificate has been
signed by a legitimate Certificate Authority.

**What it verifies:**

- Signature validity against a public key
- Public key belongs to a valid X.509 certificate
- Certificate is signed by a legitimate Certificate Authority (e.g., a Qualified
Trust Service Provider)

### 2. Verifiable Credential Validation

Location: [circuits/eudi-vc/](./circuits/eudi-vc/)

Enables privacy-preserving verification of EUDI Wallet credentials.

**What it verifies:**

- Credential was issued using a valid eIDAS e-seal
- Holder controls the holder-binding key
- Holder's key is certified by a legitimate CA/QTSP via X.509 certificate

## What this means for eIDAS and EUDI

[Learn more what these results enable](docs/eidas-meets-zkp.md)

## Use Cases

These circuits enable:

- Regulatory compliance: Meet eIDAS requirements while maximizing user privacy.
- Building a wallet framework on the existing eIDAS infrastructure with the
highest assurance level, e.g., qualified e-seals for Verifiable Credentials and
qualified e-signatures for proof of possession and cryptographic holder binding
- Unlinkability: Prove credential validity across services without creating
tracking vectors. It enables issuing one-time credentials and share them as many
time as needed without a need for batch credential issuance or one-time
credential issuance.
- Selective disclosure: Share specific attributes without revealing entire
credentials.

## Contributing

We welcome contributions! Here's how to get involved:

1. **Report issues:** Open an [issue](https://github.com/MyNextID/eudi-zk/issues) for bugs or feature requests
2. **Submit changes:** Create a [pull request](https://github.com/MyNextID/eudi-zk/pulls) with your improvements
3. **Discuss ideas:** Start a discussion before major architectural changes

Please ensure code follows existing patterns.

## License

This project is licensed under the [MIT License](./LICENSE).
