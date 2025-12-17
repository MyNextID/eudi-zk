package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

/*
CircuitJWS implements a zero-knowledge proof circuit for validating JWS (JSON
Web Signature) signatures with X.509 certificate chain verification.

Zero-Knowledge Properties:
The circuit PROVES the following statements without revealing sensitive data:
  1. A JWS signature is cryptographically valid for a given payload
  2. The signature was created using a private key whose public key is embedded in an X.509 certificate
  3. That X.509 certificate is validly signed by a Qualified Trust Service Provider (QTSP)

What remains PRIVATE (hidden from verifiers):
  - JWS protected header (contains metadata like algorithm, key ID)
  - Signer's public key (the actual key used to create the JWS signature)
  - Complete X.509 certificate of the signer that contains signer's identity information

What is PUBLIC (visible to verifiers):
  - JWS Payload (the actual data being signed)
  - QTSP's public key (the trusted authority's public key used to verify the certificate chain)

Use Case Example:
This allows proving "a document has been signed with a valid signature from using a secret key whose public key has a public key certificate issued by a  QTSP" without revealing which specific entity signed it or their certificate details.
*/

// CircuitJWS defines the complete structure of private and public circuit
// inputs. In zero-knowledge proofs, the prover knows all these values, but
// only public inputs are revealed to verifiers.
type CircuitJWS struct {
	// ===== PRIVATE INPUTS (Witness data known only to the prover) =====

	// JWSProtected contains the base64url-encoded protected header of the JWS.
	// This typically includes algorithm type (ES256), key identifiers, and
	// other metadata. Kept private to hide key identifier information that
	// could identify the signer
	JWSProtected []uints.U8 `gnark:",secret"`

	// JWSSigR and JWSSigS are the two components of the ECDSA signature (R, S
	// values).
	// For ES256, this is a signature over SHA-256(base64url(protected) || '.'
	// || base64url(payload)).  Secp256r1Fr indicates these are scalar field
	// elements of the secp256r1 (P-256) curve.
	JWSSigR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	JWSSigS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// SignerPubKeyX and SignerPubKeyY represent the signer's ECDSA public key
	// as affine coordinates.  This is the public key that corresponds to the
	// private key used to create the JWS signature.
	SignerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SignerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// CertTBSDER is the DER-encoded TBSCertificate (To Be Signed Certificate)
	// portion.
	// This is the complete certificate body before signature, containing:
	//   - Serial number, validity dates, issuer/subject DNs
	//   - The signer's public key (must match SignerPubKeyX/Y above)
	//   - Extensions and other certificate metadata
	// Kept private to hide signer's details and certificate metadata.
	// We use the TBS for easier processing within the circuit.
	CertTBSDER []uints.U8 `gnark:",secret"`

	// CertSigR and CertSigS are the ECDSA signature components of the X.509 certificate.
	// This signature is created by the QTSP over the CertTBSDER data.
	// Kept private as part of the complete certificate chain privacy.
	CertSigR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// ===== PUBLIC INPUTS (Revealed to all verifiers) =====

	// JWSPayload is the actual data being signed (e.g., a document, claim, or
	// message). This is public because verifiers need to know what is being
	// attested to. In JWS format, this is the middle component:
	// header.PAYLOAD.signature
	JWSPayload []uints.U8 `gnark:",public"`

	// QTSPPubKeyX and QTSPPubKeyY represent the QTSP's trusted public key as affine coordinates.
	// This is the root of trust - the public key of the authority that issued
	// the signer's certificate. Public because verifiers need to know which
	// trust authority is being relied upon.
	// The QTSP (Qualified Trust Service Provider) is analogous to a Certificate Authority (CA).
	QTSPPubKeyX emulated.Element[Secp256r1Fp] `gnark:",public"`
	QTSPPubKeyY emulated.Element[Secp256r1Fp] `gnark:",public"`
}

// The circuit performs three critical verification steps in sequence:
//
// Step 1: Verify the JWS signature is valid for the given payload
// Step 2: Verify the X.509 certificate signature is valid (signed by QTSP)
// Step 3: Verify the public key in the certificate matches the JWS signer's key
//
// By proving all three statements together, we establish a complete chain of
// trust: QTSP -> Certificate -> Signer's Public Key -> JWS Signature -> Payload
func (c *CircuitJWS) Define(api frontend.API) error {
	// Step 1: Verify JWS Signature
	// Proves: The JWS signature (JWSSigR, JWSSigS) is a valid ECDSA signature
	// over the message constructed from JWSProtected and JWSPayload,
	// verifiable with the signer's public key (SignerPubKeyX, SignerPubKeyY).
	//
	// This establishes: "Someone with the private key corresponding to
	// SignerPubKey created a valid signature over this specific payload."
	c.VerifyJWS(api)

	// Step 2: Verify X.509 Certificate Signature
	// Proves: The certificate signature (CertSigR, CertSigS) is a valid ECDSA
	// signature over the certificate body (CertTBSDER), verifiable with the
	// QTSP's public key (QTSPPubKeyX, QTSPPubKeyY).
	//
	// This establishes: "The QTSP (trusted authority) has certified this
	// certificate by signing it with their private key."
	c.VerifyX509Signature(api)

	// Step 3: Verify Public Key Binding
	// Proves: The public key embedded in the X.509 certificate (extracted from
	// CertTBSDER) exactly matches the public key used to verify the JWS
	// signature (SignerPubKeyX/Y).
	//
	// This is the critical link that binds the certificate chain to the JWS
	// signature.  Without this check, we could prove a valid JWS and a valid
	// certificate separately, but not that they're related to each other.
	//
	// This establishes: "The public key certified by the QTSP is the same key
	// that verified the JWS signature."
	return c.verifyPubKeyInCertificateSimplified(api)
}
