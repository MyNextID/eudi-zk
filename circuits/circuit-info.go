// Package circuits manages information about ZK circuits
package circuits

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/zkcore"
)

// Byte array sizes
const (
	ByteSize32    = 32
	ByteSize64    = 64
	ByteSizeB64   = 86
	ByteSize128   = 128
	ByteSize256   = 256
	ByteSize1024  = 1024
	ByteSize64Hex = 128
)

// CircuitInfo contains a list of circuits
type CircuitInfo struct {
	Circuit      frontend.Circuit
	Dir          string
	Name         string `json:"name"`
	Description  string `json:"description"`
	Version      uint   `json:"version"`
	InputParser  InputParser
	EndpointInfo *EndpointInfo `json:"methods"`
}

// Compile compiles a circuit and stores the circuit information locally
func (ci CircuitInfo) Compile() error {

	csPath, pkPath, vkPath := ci.FilePaths()

	return zkcore.SetupAndSave(ci.Circuit, csPath, pkPath, vkPath)
}

// FilePaths returns the circuit file paths
func (ci CircuitInfo) FilePaths() (csPath, pkPath, vkPath string) {

	csPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.ccs", ci.Name, ci.Version))
	pkPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.pk", ci.Name, ci.Version))
	vkPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.vk", ci.Name, ci.Version))

	return
}

// EndpointInfo contains information about the endpoints
type EndpointInfo struct {
	Prove  Endpoints `json:"prove"`
	Verify Endpoints `json:"verify"`
}

// Endpoints contains information about the endpoint requests/responses
type Endpoints struct {
	Request  *SchemaInfo `json:"request"`
	Response *SchemaInfo `json:"response"`
}

// InputParser converts raw input to circuit assignment
type InputParser interface {
	Parse(publicInput, privateInput []byte) (frontend.Circuit, error)
}
