package api

import (
	"fmt"
	"path/filepath"

	"github.com/consensys/gnark/frontend"
	"github.com/mynextid/eudi-zk/common"
)

// contains a list of circuits
type CircuitInfo struct {
	Circuit     frontend.Circuit
	Dir         string
	Name        string
	Version     uint
	Description string
	InputParser InputParser
	// Fields      []Field // All input fields with metadata
}

// Compile compiles a circuit and stores the circuit information locally
func (ci CircuitInfo) Compile() error {

	csPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.ccs", ci.Name, ci.Version))
	pkPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.pk", ci.Name, ci.Version))
	vkPath := filepath.Join(ci.Dir, fmt.Sprintf("%s-%d.vk", ci.Name, ci.Version))

	return common.SetupAndSave(ci.Circuit, csPath, pkPath, vkPath)
}

// CompileAll compiles all the circuits and stores them locally
func (ci CircuitInfo) CompileAll() error {
	for _, v := range CircuitList {
		err := v.Compile()
		if err != nil {
			return err
		}
	}
	return nil
}
