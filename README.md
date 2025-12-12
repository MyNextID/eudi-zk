# ZK Circuits for eIDAS and EUDI

## Overview

In this repository we design several basic ZK circuits using
[Go/Gnark](https://docs.gnark.consensys.io/) zk-SNARKS framework.

We selected Gnark as it enables to design and build circuits fast and the code
is easy to follow. The circuits are not optimized and are intended only to
showcase the different capabilities.

For the production implementation we're using the Longfellow-ZK framework that's
faster and more efficient, so that it can be easily executed on servers (where
HSM-keys are used for proof generation) or devices where non-HSM keys are being
used.

The same circuits can be implemented using other ZK frameworks, such as:

- [Longfellow-ZK](https://github.com/google/longfellow-zk)
- [zkID/OpenAC](https://pse.dev/projects/zk-id)

## Structure

- [/circuits](./circuits/): ZK Circuits
  - /{circuit-name}: folders containing one or more circuits
  - /{circuit-name}/README.md: information about the circuit(s)
  - /{circuit-name}/circuit_test.go: functions to run and test the different circuits
- [/common](./common/): Common functions reused across different functions

## Where to start

You can find the simplest circuits in the [circuits/compare-bytes](./circuits/compare-bytes) folder.

## The real deal

We are introducing three main circuits that may play an important role in the eIDAS and EUDI ecosystem:

- [eIDAS signatures](./circuits/signature-verification/) a circuit that verifies that a file has been signed with signing key that has been certified by a legitimate certificate authority or qualified trust service provider
- [JWT/JWS key binding](./circuits/key-binding/) a circuit that verifies that a holder controls a private key to which a VC has been bound and verifies
- [Credentia Presentation](./) a circuit that combines eIDAS signature and the JWT/JWS key binding

[What these results enable?](eidas-meets-zkp.md)

## License

MIT

## How to contribute?

MIT
