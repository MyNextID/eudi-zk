package decodeb64_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	decodeb64 "github.com/mynextid/eudi-zk/circuits/basic-circuits/decode-base64url"
	"github.com/mynextid/eudi-zk/zkcore"
)

func TestCompareB64API(t *testing.T) {

	byteSize := 32
	saveExamplePayload := true

	// Generate inputs
	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	zkc, err := circuits.Compile(decodeb64.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	randomBytesB64 := base64.RawURLEncoding.EncodeToString(randomBytes)

	pvtIn := decodeb64.PrivateInput{
		Bytes: randomBytesB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := decodeb64.PublicInput{
		Bytes: randomBytesB64,
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
