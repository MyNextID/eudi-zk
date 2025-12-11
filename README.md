# ZK Circuit design

## Private Inputs

JWT (header + payload + signature)
X.509 signing certificate (DER bytes)
Signing certificate public key (extracted EC point)

## Public Inputs

JWT payload
QTSP public key

## Verification Steps

- Verify payload consistency: Public payload === private payload
- Extract x5t#S256 from JWT header
- Compute SHA-256(signing_cert)
- Verify x5t matches
- Verify public key is in signing cert: Search for pubkey bytes in DER
- Verify JWT signature: ES256 with provided public key
- Parse TBS and signature from cert: Lighter DER parsing (just structure, not pubkey)
- Verify signing cert signature: ECDSA with QTSP public key
