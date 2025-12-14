package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/common"
)

// CircuitEUDI proves:
// 1. I (subject/holder) have a certificate with a subject public key
// 2. I can sign a challenge with the private key corresponding to that public key
// 3. My certificate signature is verified with the public key of the CA/QTSP(public input)
// 4. VC signature is verified with the public key of the issuer (public input)
// 5. VC contains the my (subject's) public key
// 6. Without revealing the certificate or the public key
type CircuitEUDI struct {
	// ===== PRIVATE INPUTS (prover's secrets) =====

	// The certificate (secret)
	CertBytes  []uints.U8        `gnark:",secret"`
	CertLength frontend.Variable `gnark:",secret"`
	// Certificate signature
	CertSigR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	CertSigS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// Position of subject public key in certificate (from off-circuit parsing)
	SubjectPubKeyPos frontend.Variable `gnark:",secret"`

	// The subject public key (secret - must match the subject key in the certificate)
	SubjectPubKeyX emulated.Element[Secp256r1Fp] `gnark:",secret"`
	SubjectPubKeyY emulated.Element[Secp256r1Fp] `gnark:",secret"`

	// Signature on the challenge (secret) - by the holder
	ChallengeSignatureR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	ChallengeSignatureS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// VC JWS header
	JWSProtected []uints.U8 `gnark:",secret"`
	// confirmation claim
	CnfB64            []uints.U8        `gnark:",secret"` // base64url encoded cnf part of the header
	CnfB64Position    frontend.Variable `gnark:",secret"` // cnfB64 start position in the header
	CnfKeyHexPosition frontend.Variable `gnark:",secret"` // public key position within the decoded cnfB64

	// VC Signature
	JWSR emulated.Element[Secp256r1Fr] `gnark:",secret"`
	JWSS emulated.Element[Secp256r1Fr] `gnark:",secret"`

	// ===== PUBLIC INPUTS (known to verifier) =====
	// Verifier's challenge
	Challenge []uints.U8 `gnark:",public"`
	// CA's/QTSP's Public key -- validates the subject's cert signature
	CAPubKeyX emulated.Element[Secp256r1Fp] `gnark:",public"`
	CAPubKeyY emulated.Element[Secp256r1Fp] `gnark:",public"`

	// VC issuer's public key -- validates the VC signature
	IssuerPubKeyX emulated.Element[Secp256r1Fp] `gnark:",public"`
	IssuerPubKeyY emulated.Element[Secp256r1Fp] `gnark:",public"`

	// VC Payload
	JWSPayload []uints.U8 `gnark:",public"`
}

// Define implements the circuit logic
func (c *CircuitEUDI) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// ===== STEP 1: Navigate certificate structure to find SubjectPublicKeyInfo =====
	// This proves we're at the SUBJECT's public key, not the issuer's or any other key
	subjectPubKeyPos := NavigateToSubjectPublicKeyInfoInTBS(api, uapi, c.CertBytes[:])

	// ===== STEP 2: Verify claimed position matches the proven position =====
	api.AssertIsEqual(subjectPubKeyPos, c.SubjectPubKeyPos)

	// ===== STEP 3: Extract subject public key from certificate =====
	extractedPubKey := ExtractSubjectPublicKeyFromCert(
		api,
		uapi,
		c.CertBytes[:],
		subjectPubKeyPos, // Use the proven position
	)

	// ===== STEP 4: Verify extracted key matches the claimed public key =====
	// common.CompareBytes(api, extractedPubKey, circuit.SignerPubKeyBytes)
	common.ComparePublicKeys(api, c.SubjectPubKeyX, c.SubjectPubKeyY, extractedPubKey)

	// ===== STEP 5: Verify signature on challenge =====
	publicKey := ecdsa.PublicKey[Secp256r1Fp, Secp256r1Fr]{
		X: c.SubjectPubKeyX,
		Y: c.SubjectPubKeyY,
	}

	signature := ecdsa.Signature[Secp256r1Fr]{
		R: c.ChallengeSignatureR,
		S: c.ChallengeSignatureS,
	}

	common.VerifyES256(api, c.Challenge, publicKey, signature)

	// ==== STEP 6: Verify the Certificate Signature ====
	caPublicKey := ecdsa.PublicKey[Secp256r1Fp, Secp256r1Fr]{
		X: c.CAPubKeyX,
		Y: c.CAPubKeyY,
	}

	certSignature := ecdsa.Signature[Secp256r1Fr]{
		R: c.CertSigR,
		S: c.CertSigS,
	}

	common.VerifyES256(api, c.CertBytes, caPublicKey, certSignature)

	// ===== STEP 7: Verify the VC (JWS) signature =====
	issuerPublicKey := ecdsa.PublicKey[Secp256r1Fp, Secp256r1Fr]{
		X: c.IssuerPubKeyX,
		Y: c.IssuerPubKeyY,
	}

	jws := ecdsa.Signature[Secp256r1Fr]{
		R: c.JWSR,
		S: c.JWSS,
	}

	common.VerifyJWS(api, c.JWSProtected, c.JWSPayload, issuerPublicKey, jws)

	// ===== STEP 8: Verify that the subject key == confirmation key ==
	subjectPublicKeyDigest := common.PublicKeyDigest(api, c.SubjectPubKeyX, c.SubjectPubKeyY)

	common.VerifyCnf(api, c.JWSProtected, c.CnfB64, c.CnfB64Position, c.CnfKeyHexPosition, subjectPublicKeyDigest)

	return nil
}
