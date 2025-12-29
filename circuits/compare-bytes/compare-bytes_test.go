package ccb_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
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

func TestCompareBytesV2(t *testing.T) {

	// TODO: the limit is set within the circuit but we don't check it explicitly
	byteSize := 64

	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	zkc, err := circuits.Compile(ccb.CBInfo)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// Create witness assignment with actual values
	assignment := &ccb.CBCircuit{
		// Private inputs
		SecretBytes: zkcore.BytesToU8Array(randomBytes),
		// Public inputs
		PublicBytes: zkcore.BytesToU8Array(randomBytes),
	}

	proof, err := zkc.Prove(assignment)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// Create public witness assignment with actual values
	assignmentPublic := &ccb.CBCircuit{
		// Public inputs
		PublicBytes: zkcore.BytesToU8Array(randomBytes),
	}

	err = zkc.Verify(assignmentPublic, proof)
	if err != nil {
		t.Fatalf("failed to verify a proof: %v", err)
	}

}

func TestCompareBytesAPI(t *testing.T) {

	// TODO: the limit is set within the circuit but we don't check it explicitly
	byteSize := 64
	saveExamplePayload := true

	// Generate inputs
	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	zkc, err := circuits.Compile(ccb.CBInfo)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	randomBytesB64 := base64.RawURLEncoding.EncodeToString(randomBytes)

	pvtIn := ccb.CBPrivateInput{
		BytesB64Url: randomBytesB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := ccb.CBPublicInput{
		BytesB64Url: randomBytesB64,
	}
	pubInBuf, _ := json.Marshal(pubIn)

	// create a proof
	proof, err := zkc.ProveWithJSON(pubInBuf, pvtInBuf)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// verify the proof
	err = zkc.VerifyWithJSON(pubInBuf, proof)
	if err != nil {
		t.Fatalf("failed to verify a proof: %v", err)
	}

	// save the sample payload
	if saveExamplePayload {
		proveRequest := circuits.Request{
			Private: pvtIn,
			Public:  pubIn,
		}

		err = proveRequest.Save("examples/compare-bytes-prove.json")
		if err != nil {
			t.Fatal(err)
		}
	}

}
