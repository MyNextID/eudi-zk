package ccb_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/zkcore"
)

func TestCircuitCompareSubset(t *testing.T) {

	ccsPath := "compiled/circuit-cs-v1.ccs"
	pkPath := "compiled/proving-cs-v1.key"
	vkPath := "compiled/verifying-cs-v1.key"

	forceCompile := true

	byteSize := 64
	subsetSize := 32
	position := 13

	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytes2, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	// Extract subset from the random bytes (make a proper copy)
	subset := make([]byte, subsetSize)
	copy(subset, randomBytes[position:position+subsetSize])

	circuitTemplate := &ccb.CircuitCompareSubset{
		Bytes:  make([]uints.U8, byteSize),
		Subset: make([]uints.U8, subsetSize),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitCompareSubset{
		// Private inputs
		Bytes:         zkcore.BytesToU8Array(randomBytes),
		PositionStart: position,
		// Public inputs
		Subset: zkcore.BytesToU8Array(subset),
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
	zkcore.TestCircuitSimple(assignment, ccs, pk, vk)

}
