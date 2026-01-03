// Package circuits manages information about ZK circuits
package circuits

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/zkcore"
)

// CircuitInfo contains a list of circuits
type CircuitInfo struct {
	Circuit         frontend.Circuit
	Dir             string
	Name            string `json:"name"`
	Description     string `json:"description"`
	LongDescription string `json:"longDescription"`
	Version         uint   `json:"version"`
	InputParser     InputParser
	EndpointInfo    *EndpointInfo `json:"methods"`
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

// Constraints defines the variable constraints
type Constraints struct {
	Min         int    `json:"min,omitempty"`
	Max         int    `json:"max,omitempty"`
	Description string `json:"description,omitempty"`
}

// EndpointInfo contains information about the endpoints
type EndpointInfo struct {
	Constraints map[string]Constraints `json:"constraints,omitempty"`
	Prove       Endpoints              `json:"prove"`
	Verify      Endpoints              `json:"verify"`
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
