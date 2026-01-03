package verifyjwscert

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/mynextid/eudi-zk/zkcore"
)

// VerifyJWS combines a protected JWS header with the payload and verifies the
// signature using the provided public keys. Only for ES256
// Assumptions:
// - protected header contains all the non-PII metadata and is a private input
// - payload contains all user info and is a public input
// - selective disclosure of the user info is out of scope of this circuit as we'll address it later
func (c *Circuit) VerifyJWS(api frontend.API) error {
	bytesAPI, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// Initialize SHA256 hash
	hash, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Build complete message buffer: protected + '.' + payload
	maxMessageSize := MaxJWSProtectedBytes + 1 + MaxJWSPayloadBytes
	message := make([]uints.U8, maxMessageSize)

	// Initialize with zeros
	for i := range message {
		message[i] = uints.NewU8(0)
	}

	// Copy protected header bytes to beginning of message
	copy(message, c.JWSProtected)

	// Place dot separator at the position indicated by ProtectedSize
	// We need to conditionally place it at the correct position
	dotSeparator := uints.NewU8(46)
	for i := range message {
		isDotPosition := api.IsZero(api.Sub(i, c.ProtectedSize))
		message[i] = bytesAPI.Select(isDotPosition, dotSeparator, message[i])
	}

	// Copy payload bytes starting after the dot
	// Position = ProtectedSize + 1
	for i := range c.JWSPayload {
		payloadSourceIndex := i
		messageTargetIndex := api.Add(c.ProtectedSize, i+1)

		// Conditionally copy to the correct position
		for j := range message {
			isTargetPosition := api.IsZero(api.Sub(j, messageTargetIndex))
			message[j] = bytesAPI.Select(isTargetPosition, c.JWSPayload[payloadSourceIndex], message[j])
		}
	}

	// Write entire message buffer to hasher
	hash.Write(message)

	// Calculate actual message length: ProtectedSize + 1 (dot) + PayloadSize
	actualLength := api.Add(api.Add(c.ProtectedSize, 1), c.PayloadSize)

	// Compute hash of only the first actualLength bytes
	messageHash := hash.FixedLengthSum(actualLength)

	// Convert to fixed array if needed
	var hashArray [32]uints.U8
	copy(hashArray[:], messageHash)

	// Assert computed hash matches expected hash
	zkcore.AssertIsEqualBytes(api, c.Hash[:], hashArray[:])

	// Convert to P256Fr
	mHash, err := zkcore.Sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.SignerPubKeyX,
		Y: c.SignerPubKeyY,
	}
	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.JWSSigR,
		S: c.JWSSigS,
	}

	// Verify the signature
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}
