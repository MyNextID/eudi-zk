package overxx_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	overxx "github.com/mynextid/eudi-zk/circuits/temporal"
	"github.com/mynextid/eudi-zk/models"
)

func TestOver18(t *testing.T) {

	saveExamplePayload := true
	// == create test data ==

	// min date of birth value must be such that people born before that date are considered of age
	thresholdDate := "2004-01-01"
	claim := "birthdate"

	payload := models.GetDemoPID()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	zkc, err := circuits.Compile(overxx.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}
	pvtIn := overxx.PrivateInput{
		Payload: payloadB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := overxx.PublicInput{
		ThresholdDate: thresholdDate,
		Claim:         claim,
	}
	pubInBuf, _ := json.Marshal(pubIn)

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
