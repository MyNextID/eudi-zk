# ZK Circuits

The focus of these circuts is to showcase different capabilities and use cases,
while maintainging simplicity. We are not trying to optimize the operations for
production use.

Optimized and production circuits will be published separately.

## Setting the scene

ZK circuits are built using [Gnark v0.14](https://pkg.go.dev/github.com/consensys/gnark)

Tested cryptography:

- Elliptic Curves: secp256r1
- SHA256

Tested encodings:

- DER
- hex
- base64url

## Circuits

Every folder contains one or more circuits.

- [compare-bytes](./compare-bytes/) basic circuits to test simple functions
- [key-binding](./key-binding/) testing different approaches to validate the VC key binding (e.g., via cnf and key digest)
- [verify-eidas-signature](./verify-eidas-signature/) testing JWS and DER signature validation

## Structure

- `/{circuit-name}/README.md`: information about the circuit(s)
- `/{circuit-name}/circuit_test.go`: functions to run and test the different circuits
- `/{circuit-name}/compiled`: folder where circuits, prooving and verification keys are stored

## Running the circuits

To test the circuits you need [GO v1.24.2 or higher](https://go.dev/doc/install)

All circuits can be executed by running test functions like:

`go test -v -timeout 5m -run ^TestCompareDigestPubKeys$ github.com/mynextid/eudi-zk/circuits/compare-bytes`
