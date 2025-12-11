# Circuit: Signature Verification

Version: 1

## Artefacts

- Verifiable Credential (VC) signed using JWT or JWS. JWT/JWS consists of three main parts: protected header, payload, signature
- Signer's:
  - secret key: to sign the VC
  - public key: to verify the VC signature
  - public key certificate (X.509): to verify that the key has been recognised by a Certificate Authority (e.g., QTSP)
- Certificate Issuer's:
  - secret key: to sign the signer's public key certificate
  - public key: to verify the signature of the signer's public key certificate
  - public key certificate (X.509): to verify the trust chain

## Private inputs

These artefacts are known only to the proofer and are not revealed to the
verifier:

- protected JWT/JWS header (we assume all non-PII signature metadata is in the protected header and not in the payload)
- signer's public key
- signer's public key certificate

## Public inputs

These artefacts are known to both the proofer and the verifier and the verifier
is using them as input to the verification function

- VC payload
- Certificate issuer's public key. Note: Issuer's certificate (chain) is verified outside of the ZK circuit

## ZK Circuit Verification Functions

- verify the VC signature (JWT/JWS)
  - construct the JWT_message = base64url(header) || '.' || base64url(payload)
  - compute the digest
  - validate the signature
- verify that the signer's public key is in the x509 DER cert
- verify that the CA's public key verifies the signature of the signer's x509 certificate