package ccb_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/common"
)

func TestCircuitLex(t *testing.T) {
	ccsPath := "compiled/cb-circuit-lex-v1.ccs"
	pkPath := "compiled/cb-proving-lex-v1.key"
	vkPath := "compiled/cb-verifying-lex-v1.key"

	forceCompile := true

	// == create test data ==
	reference := []byte("2024-09-12")
	smaller := []byte("2023-09-11")
	greater := []byte("2024-09-21")
	equal := reference
	fmt.Println(reference)
	fmt.Println(smaller)
	fmt.Println(greater)

	circuitTemplate := &ccb.CircuitLex{
		StringReferenceBytes: make([]uints.U8, len(reference)),
		StringSmallerBytes:   make([]uints.U8, len(smaller)),
		StringGreaterBytes:   make([]uints.U8, len(greater)),
		StringEqualBytes:     make([]uints.U8, len(equal)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitLex{
		StringReferenceBytes: common.BytesToU8Array(reference),
		StringSmallerBytes:   common.BytesToU8Array(smaller),
		StringGreaterBytes:   common.BytesToU8Array(greater),
		StringEqualBytes:     common.BytesToU8Array(equal),
		Positive:             1,
		Negative:             -2,
		Zero:                 0,
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)

}
