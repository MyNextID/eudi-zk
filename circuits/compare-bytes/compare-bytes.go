package ccb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
	"github.com/mynextid/eudi-zk/common"
)

// CBCircuit inputs for the compare-bytes circuit
type CBCircuit struct {
	// Secret input
	Bytes []uints.U8 `gnark:",secret"`

	// Public input
	PubBytes []uints.U8 `gnark:",public"`
}

// Define defines the circuit logic
func (c *CBCircuit) Define(api frontend.API) error {

	common.AssertIsEqualBytes(api, c.Bytes, c.PubBytes)

	return nil
}

// ==== API data models ====
type PublicInput struct {
	Bytes string `json:"bytes_b64url" description:"BASE64URL encoded byte array"`
}

type PrivateInput struct {
	Bytes string `json:"bytes_b64url" description:"BASE64URL encoded byte array"`
}

// ==== Endpoint: /prove ===
type CBProveRequest struct {
	Public  PublicInput  `json:"public" description:"Public ZK circuit inputs"`
	Private PrivateInput `json:"private" description:"Private ZK circuit inputs"`
}
type CBProveResponse struct {
	Proof string `json:"proof" description:"BASE64URL encoded response"`
}

// ==== Endpoint: /verify ===
type CBVerifyRequest struct {
	Public PublicInput `json:"public" description:"Public ZK circuit inputs"`
	Proof  string      `json:"proof" description:"BASE64URL encoded ZK proof"`
}
type CBVerifyResponse struct {
	Success string  `json:"success"`
	Valid   bool    `json:"valid"`
	Message *string `json:"message,omitempty"`
}

// ==== Circuit info ===

var CBInfo = &circuits.CircuitInfo{
	Circuit: &CBCircuit{
		Bytes:    make([]uints.U8, circuits.BYTE_SIZE64),
		PubBytes: make([]uints.U8, circuits.BYTE_SIZE64),
	},
	Name:        "compare-bytes",
	Description: "The circuit compares two byte arrays and returns an error if the inputs are different",
	Version:     1,
	InputParser: &CircuitBytesAPI{},
	EndpointInfo: &circuits.EndpointInfo{
		Prove: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBProveRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBProveResponse{}, nil),
		},
		Verify: circuits.Endpoints{
			Request:  circuits.CreateSchemaInfo("application/json", CBVerifyRequest{}, nil),
			Response: circuits.CreateSchemaInfo("application/json", CBVerifyResponse{}, nil),
		},
	},
}

// ==== input parser ====
type CircuitBytesAPI struct{}

func (p *CircuitBytesAPI) Parse(publicInput, privateInput []byte) (frontend.Circuit, error) {
	var pub PublicInput
	var pvt PrivateInput

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

	return &CBCircuit{
		Bytes:    common.BytesToU8Array(pvtBytes),
		PubBytes: common.BytesToU8Array(pubBytes),
	}, nil
}
