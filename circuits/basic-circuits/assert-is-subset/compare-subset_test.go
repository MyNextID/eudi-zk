package assertissubset_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	assertissubset "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-is-subset"
	"github.com/mynextid/eudi-zk/zkcore"
)

func TestCircuitCompareSubset(t *testing.T) {

	saveExamplePayload := true

	zkc, err := circuits.Compile(assertissubset.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	byteSize := 64
	subsetSize := 32
	position := 13

	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytesB64 := base64.RawURLEncoding.EncodeToString(randomBytes)
	randomBytes2, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	_ = randomBytes2

	// Extract subset from the random bytes (make a proper copy)
	subset := make([]byte, subsetSize)
	copy(subset, randomBytes[position:position+subsetSize])
	subsetB64 := base64.RawURLEncoding.EncodeToString(subset)

	pvtIn := assertissubset.PrivateInput{
		Bytes:         randomBytesB64,
		PositionStart: position,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := assertissubset.PublicInput{
		Subset: subsetB64,
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

		filename := fmt.Sprintf("%s.json", zkc.Info.Name)
		path := filepath.Join("examples", filename)
		err = proveRequest.Save(path)
		if err != nil {
			t.Fatal(err)
		}
	}

}
