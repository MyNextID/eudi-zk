package comparelex_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	comparelex "github.com/mynextid/eudi-zk/circuits/basic-circuits/compare-lexicographically"
)

func TestCircuitLex(t *testing.T) {

	saveExamplePayload := true
	zkc, err := circuits.Compile(comparelex.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// == create test data ==
	reference := "2024-09-12"
	toCompare := []string{
		"2023-09-11", // smaller
		"2024-09-21", // greater
		reference,    // equal
	}
	expectedResult := []int{1, 0, 0}

	pvtIn := comparelex.PrivateInput{
		StringA: reference,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)

	for i, v := range toCompare {
		pubIn := comparelex.PublicInput{
			StringB: v,
			Result:  expectedResult[i],
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

}
