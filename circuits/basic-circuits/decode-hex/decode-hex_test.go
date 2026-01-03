package decodehex_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	decodehex "github.com/mynextid/eudi-zk/circuits/basic-circuits/decode-hex"
)

func TestCompareHex(t *testing.T) {

	saveExamplePayload := true
	zkc, err := circuits.Compile(decodehex.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)

	pubKeyBytesHex := hex.EncodeToString(pubKeyBytes)

	pvtIn := decodehex.PrivateInput{
		Bytes: pubKeyBytesHex,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := decodehex.PublicInput{
		BytesHex: pubKeyBytesHex,
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
