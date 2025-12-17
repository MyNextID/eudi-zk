package ccb

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

// Circut checks:
// - whether the base64url encoded cnf is in the base64url encoded protected JWS header
// - decodes the cnf
// - extracts the hex-encoded public key digest
// - decodes the hex-encoded public key digest
// - compares the extracted public key digest with the provided public key bytes
type CircuitCompareCnf struct {
	// Secret input
	HeaderB64         []uints.U8        `gnark:",secret"` // base64url encoded protected header
	CnfB64            []uints.U8        `gnark:",secret"` // base64url encoded cnf part of the header
	CnfB64Position    frontend.Variable `gnark:",secret"` // cnfB64 start position in the header
	PubKeyHexPosition frontend.Variable `gnark:",secret"` // public key position within the decoded cnfB64

	// Public input
	PublicKeyDigest []uints.U8 `gnark:",public"` // uncompressed public key
}

func (c *CircuitCompareCnf) Define(api frontend.API) error {

	// Verify whether cnfB64 is a subset of headerB64
	err := common.IsSubset(api, c.HeaderB64, c.CnfB64, c.CnfB64Position)
	if err != nil {
		return err
	}

	// Decode the header
	cnf, err := common.DecodeBase64Url(api, c.CnfB64)
	if err != nil {
		return err
	}

	// Extract the hex encoded public key
	pubKeyHexLength := 64 // size of the hex encoded SHA256 digest
	publicKeyHex := common.GetSubset(api, cnf, c.PubKeyHexPosition, pubKeyHexLength)

	// Decode the hex encoded public key
	publicKeyDigest, err := common.DecodeHex(api, publicKeyHex)
	if err != nil {
		return err
	}

	// compare the bytes
	common.AssertIsEqualBytes(api, publicKeyDigest, c.PublicKeyDigest)

	return nil
}
