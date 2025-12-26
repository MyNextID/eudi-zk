package ccb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitBytes struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	PubBytes []uints.U8 `gnark:",public"`
}

func (c *CircuitBytes) Define(api frontend.API) error {

	// Compare the digests byte by byte using the Val() method to access the underlying variable
	common.AssertIsEqualBytes(api, c.Bytes, c.PubBytes)

	return nil
}

type CircuitBytesPublicInput struct {
	Bytes string `json:"bytes_b64url"`
}

type CircuitBytesPrivateInput struct {
	Bytes string `json:"bytes_b64url"`
}

// CircuitBytesInputParser for CircuitB64Url
type CircuitBytesInputParser struct{}

func (p *CircuitBytesInputParser) Parse(publicInput, privateInput []byte) (frontend.Circuit, error) {
	var pub CircuitBytesPublicInput
	var pvt CircuitBytesPrivateInput

	if err := json.Unmarshal(publicInput, &pub); err != nil {
		return nil, fmt.Errorf("failed to parse public input: %w", err)
	}
	if err := json.Unmarshal(privateInput, &pvt); err != nil {
		return nil, fmt.Errorf("failed to parse private input: %w", err)
	}

	// Decode
	pubBytes, err := base64.RawURLEncoding.DecodeString(pub.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode the public input: %v", pubBytes)
	}
	pvtBytes, err := base64.RawURLEncoding.DecodeString(pvt.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode the public input: %v", pubBytes)
	}

	return &CircuitBytes{
		Bytes:    common.BytesToU8Array(pvtBytes),
		PubBytes: common.BytesToU8Array(pubBytes),
	}, nil
}
