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

- [Longfellow-ZK](https://github.com/google/longfellow-zk) -
[zkID/OpenAC](https://pse.dev/projects/zk-id)

## Where to start

Go to [circuits](./circuits/README.md) or to the
[circuits/compare-bytes](./circuits/compare-bytes/README.md) folder.

## The real deal

We are introducing two main circuits that may play an important role in the
eIDAS and EUDI ecosystem:

- [VC validation](./circuits/der-x509-lookup/README.md) a circuit that verifies
that a holder controls a private key to which a VC has been bound and verifies -
[eIDAS signatures](./circuits/signature-verification/) a circuit that verifies
that a file has been signed with signing key that has been certified by a
legitimate certificate authority or qualified trust service provider

[What these results enable?](eidas-meets-zkp.md)

## License

MIT

## How to contribute?

1. Open an issue 2. Create a PR
