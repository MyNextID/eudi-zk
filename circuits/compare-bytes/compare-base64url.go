package ccb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

type CircuitB64Url struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	BytesB64 []uints.U8 `gnark:",public"`
}

func (c *CircuitB64Url) Define(api frontend.API) error {
	// Decode base64url
	decodedBytes, _ := common.DecodeBase64Url(api, c.BytesB64)

	// Compare the bytes
	common.AssertIsEqualBytes(api, c.Bytes, decodedBytes)

	return nil
}

type CircuitB64UrlPublicInput struct {
	// Public input
	Bytes string `json:"bytes_b64url"`
}
type CircuitB64UrlPrivateInput struct {

	// Secret input
	Bytes string `json:"bytes_b64url"`
}

type CircuitB64UrlAPI struct{}

func (api CircuitB64UrlAPI) Parse(publicInput, privateInput []byte) (frontend.Circuit, error) {
	var pub CircuitB64UrlPublicInput
	var pvt CircuitB64UrlPrivateInput

	if err := json.Unmarshal(publicInput, &pub); err != nil {
		return nil, fmt.Errorf("failed to parse public input: %w", err)
	}
	if err := json.Unmarshal(privateInput, &pvt); err != nil {
		return nil, fmt.Errorf("failed to parse private input: %w", err)
	}

	// Decode
	// we decode the public input within the circuit
	pubBytes := []byte(pub.Bytes)

	// we decode the private input at the API level
	pvtBytes, err := base64.RawURLEncoding.DecodeString(pvt.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to base64url decode the public input: %v", pubBytes)
	}

	return &CircuitB64Url{
		Bytes:    common.BytesToU8Array(pvtBytes),
		BytesB64: common.BytesToU8Array(pubBytes),
	}, nil
}
