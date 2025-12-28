package circuits

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/common"
)

const (
	BYTE_SIZE32     = 32
	BYTE_SIZE64     = 64
	BYTE_SIZE64_B64 = 86
	BYTE_SIZE128    = 128
	BYTE_SIZE1024   = 1024
	BYTE_SIZE64_HEX = 128
)

// contains a list of circuits
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

	return common.SetupAndSave(ci.Circuit, csPath, pkPath, vkPath)
}

// FilePaths returns the circuit file paths
func (ci CircuitInfo) FilePaths() (csPath, pkPath, vkPath string) {

	csPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.ccs", ci.Name, ci.Version))
	pkPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.pk", ci.Name, ci.Version))
	vkPath = filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.vk", ci.Name, ci.Version))

	return
}

type EndpointInfo struct {
	Prove  Endpoints `json:"prove"`
	Verify Endpoints `json:"verify"`
}

type Endpoints struct {
	Request  *SchemaInfo `json:"request"`
	Response *SchemaInfo `json:"response"`
}

// InputParser converts raw input to circuit assignment
type InputParser interface {
	Parse(publicInput, privateInput []byte) (frontend.Circuit, error)
}
