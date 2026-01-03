# Version 2

This folder contains various basic ZK circuits. Our goal is to showcase the
fundamental logic and operations that will later serve as building blocks for
more complex ZK circuits.

This folder includes the following ZK circuits:

- [Assert is equal](./assert-is-equal/) - Defines a zero-knowledge circuit that
proves two byte arrays are equal without revealing the secret byte array.
- [Assert cnf](./assert-cnf/) - Proves that a JWS protected header contains a
specific cnf claim with a public key digest that matches a given value, without
revealing the full header.
- [Decode BASE64URL](./decode-base64url/) - Decodes base64url-encoded payload
and compares it against a reference value.
- [Decode hex](./decode-hex/) - Decodes hex-encoded payload and compares it
against a reference value.
- [Assert EC Public Key](./assert-ec-public-key/) - Transforms elliptic curve
public key X and Y components into an uncompressed form.
- [Assert EC Public Key Digest](./assert-ec-public-key-digest/) - Transforms
elliptic curve public key X and Y components into an uncompressed form and
compares the public key digests.
- [Compare Lexicographically](./compare-lexicographically/) - Proves the
lexicographical ordering relationship between a secret string and a public
string without revealing the secret. Returns 1 if secret < public, 0 otherwise.
- [Assert is subset](./assert-is-subset/) - Proves that a public subset exists
within a secret byte array at a secret position, without revealing the full
array or position.
