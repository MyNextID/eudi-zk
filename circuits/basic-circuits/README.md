# Basic simple circuits

Version: 2

In this folder you can find various basic ZK circuits. Our goal is to showcase
the basic logic and operations that will later act as building blocks for more
complex ZK circuits.

here you can find the following ZK circuits:

- [Assert is equal](./assert-is-equal/) defines a zero-knowledge circuit that
proves two byte arrays are equal without revealing the secret byte array.
- [Assert cnf](./assert-cnf/) circuit proves that a JWS protected header
contains a specific cnf claim with a public key digest that matches a given
value, WITHOUT revealing the full header.
- [Decode BASE64URL](./decode-base64url/) circuit decodes base64url encoded
payload and compares it against the reference value.
- [Decode Hex](./decode-hex/) circuit decodes hex encoded payload and compares
it against the reference value.
- [Assert EC Public Key](./assert-ec-public-key/) circuit transform elliptic
curve public key X, Y components into an uncompressed form.
- [Compare Lexicographically](./compare-lexicographically/) proves lexicographical ordering
relationship between a secret string and a public string without revealing the
secret. Returns 1 if secret < public, 0 otherwise.
- [Assert is subset](./assert-is-subset/) proves that a public subset exists
within a secret byte array at a secret position, without revealing the full
array or position.
