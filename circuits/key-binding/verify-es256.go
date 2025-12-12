package ckb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

func (c *JWTCircuit) VerifyJWT(api frontend.API) error {
	// Initialize SHA256 hasher
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Concatenate header and payload with a '.' separator (ASCII 46 = 0x2E)
	// JWT format: base64url(header).base64url(payload)
	dotSeparator := uints.NewU8(46)

	// Write header to hasher
	hasher.Write(c.JWTHeaderB64)

	// Write dot separator
	hasher.Write([]uints.U8{dotSeparator})

	// Write payload to hasher
	hasher.Write(c.JWTPayloadPublic)

	// Compute SHA256 hash of header.payload
	messageHash := hasher.Sum()

	mHash, err := sha256ToP256Fr(api, messageHash)
	if err != nil {
		return err
	}
	_ = mHash

	Pub := ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
		X: c.SignerPubKeyX,
		Y: c.SignerPubKeyY,
	}
	_ = Pub
	Sig := ecdsa.Signature[emulated.P256Fr]{
		R: c.JWTSigR,
		S: c.JWTSigS,
	}

	// // signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), mHash, &Sig)

	return nil
}

// sha256ToP256Fr converts SHA256 hash output ([]uints.U8) to P256Fr field element
// This version correctly handles the emulated field limb structure
func sha256ToP256Fr(api frontend.API, hash []uints.U8) (*emulated.Element[emulated.P256Fr], error) {
	if len(hash) != 32 {
		panic("SHA256 hash must be 32 bytes")
	}

	field, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}

	// P256Fr uses 4 limbs of 64 bits each (standard for 256-bit fields in gnark)
	// Limbs are stored in little-endian order
	const nbLimbs = 4
	const bytesPerLimb = 8

	limbs := make([]frontend.Variable, nbLimbs)

	// Pack bytes into limbs (little-endian limb order)
	// hash[0..7] -> limb[0] (least significant)
	// hash[8..15] -> limb[1]
	// hash[16..23] -> limb[2]
	// hash[24..31] -> limb[3] (most significant)
	for i := 0; i < nbLimbs; i++ {
		var limbVal frontend.Variable = 0

		// Process 8 bytes for this limb (little-endian within limb)
		for j := 0; j < bytesPerLimb; j++ {
			// Read from end of hash going backwards (to match little-endian)
			byteIdx := len(hash) - 1 - (i*bytesPerLimb + j)

			if byteIdx >= 0 && byteIdx < len(hash) {
				// Shift: multiply by 2^(j*8) = 256^j
				shift := frontend.Variable(1)
				for k := 0; k < j; k++ {
					shift = api.Mul(shift, 256)
				}
				limbVal = api.Add(limbVal, api.Mul(hash[byteIdx].Val, shift))
			}
		}

		limbs[i] = limbVal
	}

	// Create element with properly structured limbs
	result := &emulated.Element[emulated.P256Fr]{
		Limbs: limbs,
	}

	// Reduce to ensure it's in the correct range
	return field.Reduce(result), nil
}
