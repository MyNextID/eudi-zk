package assertecpubkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mynextid/eudi-zk/circuits"
	assertecpubkey "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-ec-public-key"
)

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

func TestComparePubKeys(t *testing.T) {
	saveExamplePayload := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	zkc, err := circuits.Compile(assertecpubkey.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)
	pkX := pubKeyBytes[1:33]
	pkY := pubKeyBytes[33:]

	pkXB64 := base64.RawURLEncoding.EncodeToString(pkX)
	pkYB64 := base64.RawURLEncoding.EncodeToString(pkY)

	pvtIn := assertecpubkey.PrivateInput{
		PubKeyX: pkXB64,
		PubKeyY: pkYB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := assertecpubkey.PublicInput{
		PubKeyXBytes: pkXB64,
		PubKeyYBytes: pkYB64,
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
