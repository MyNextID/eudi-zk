# Circuit: byte comparison and decoding

Version: 2

In this folder you can find various basic ZK circuits. The goal of these
circuits is to showcase the basic logic and operations that will later act as
building blocks for more complex ZK circuits.

You can find the following circuits:

- [Assert is equal](./assert-is-equal/) defines a zero-knowledge circuit that
proves two byte arrays are equal without revealing the secret byte array.
- [Assert cnf](./assert-cnf/) circuit proves that a JWS protected header
contains a specific cnf claim with a public key digest that matches a given
value, WITHOUT revealing the full header.
- [Decode BASE64URL](./decode-base64url/) circuit decodes base64url encoded
payload and compares it against the reference value.
