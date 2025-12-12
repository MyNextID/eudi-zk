# Circuit: byte comparison and decoding

Version: 1

Here we test different decoding and public key transformation functions within ZK circuits.

In this repository we have the following test circuits:

- compare-bytes: performs simple byte-by-byte comparison
- compare-hex: performs hex decoding + byte comparison
- compare-public-keys: performs byte comparison of x and y components of elliptic curve public keys
- compare-digest-public-keys: computes a hash of an elliptic curve public key
- compare-base64url: performs base64url and hex decoding and compares it with the original byte array

All the tests can be run using test functions in [circuit_test](./circuit_test.go)

Note: some take longer than the default 30s test limit (increase the test limit as required)

All the circuits and proving and verification keys are stored in the [compiled](./compiled/) folder.
