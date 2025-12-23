package ct

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

// Circuit functions
// - check that the VC is of the correct type -> IsSubset
// - check that the date of birth is part of the VC payload -> IsSubset
// - extract the date of birth -> Decode
// - compare the date of birth with the current date
type Temporal struct {
	// Secret input
	Payload []uints.U8 `gnark:",secret"` // base64url encoded protected header
	// Secret input
	DateB64         []uints.U8        `gnark:",public"` // base64url encoded date of the VC
	DateB64Position frontend.Variable `gnark:",public"` // start position in the payload
	DatePosition    frontend.Variable `gnark:",public"` // date position within the claim

	// Public input
	PublicKeyDigest  []uints.U8        `gnark:",public"` // uncompressed public key
	TypB64           []uints.U8        `gnark:",public"` // base64url encoded type of the VC
	TypB64Position   frontend.Variable `gnark:",public"` // start position in the payload
	TypPosition      frontend.Variable `gnark:",public"` // type position within the claim
	TimeOfValidation frontend.Variable `gnark:",public"` // type of validation
	Diff             frontend.Variable `gnark:",public"` // difference between the dates in days
}

func (c *Temporal) Define(api frontend.API) error {

	// Verify that the date is member of the payload
	err := common.IsSubset(api, c.Payload, c.DateB64, c.DateB64Position)
	if err != nil {
		return err
	}

	// Verify that the typ is member of the payload
	err = common.IsSubset(api, c.Payload, c.TypB64, c.TypB64Position)
	if err != nil {
		return err
	}

	// Decode the header
	cnf, err := common.DecodeBase64Url(api, c.DateB64)
	if err != nil {
		return err
	}

	// Extract the hex encoded public key
	size := 10 // size of the date/time element in bytes (YYYY-MM-DD: 10 characters == 10 bytes)
	date := common.GetSubset(api, cnf, c.DatePosition, size)

	_ = date
	// CompareDates(date, c.TimeOfValidation, c.Diff)

	return nil
}
