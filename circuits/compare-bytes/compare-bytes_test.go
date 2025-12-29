package ccb_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/zkcore"
)

func TestCompareBytes(t *testing.T) {
	ccsPath := "compiled/cb-circuit-v1.ccs"
	pkPath := "compiled/cb-proving-v1.key"
	vkPath := "compiled/cb-verifying-v1.key"

	forceCompile := true

	byteSize := 1024

	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytes2, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	circuitTemplate := &ccb.CBCircuit{
		SecretBytes: make([]uints.U8, byteSize),
		PublicBytes: make([]uints.U8, byteSize),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CBCircuit{
		// Private inputs
		SecretBytes: zkcore.BytesToU8Array(randomBytes),
		// Public inputs
		PublicBytes: zkcore.BytesToU8Array(randomBytes),
	}
	_ = randomBytes2

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := zkcore.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	zkcore.TestCircuit(assignment, ccs, pk, vk)

}
