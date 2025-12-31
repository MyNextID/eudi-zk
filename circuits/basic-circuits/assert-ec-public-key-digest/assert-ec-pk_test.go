package assertecpubkeyd_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/mynextid/eudi-zk/circuits"
	assertecpubkeyd "github.com/mynextid/eudi-zk/circuits/basic-circuits/assert-ec-public-key-digest"
)

// Secp256r1Fp field parameters
type Secp256r1Fp = emulated.P256Fp

// Secp256r1Fr field parameters
type Secp256r1Fr = emulated.P256Fr

func TestCompareDigestPubKeys(t *testing.T) {
	saveExamplePayload := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	zkc, err := circuits.Compile(assertecpubkeyd.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)
	pkX := pubKeyBytes[1:33]
	pkY := pubKeyBytes[33:]
	pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)

	pkXB64 := base64.RawURLEncoding.EncodeToString(pkX)
	pkYB64 := base64.RawURLEncoding.EncodeToString(pkY)
	pkB64 := base64.RawURLEncoding.EncodeToString(pubKeyBytes)
	dB64 := base64.RawURLEncoding.EncodeToString(pubKeyBytesDigest[:])

	pvtIn := assertecpubkeyd.PrivateInput{
		PubKeyX: pkXB64,
		PubKeyY: pkYB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := assertecpubkeyd.PublicInput{
		PubKeyBytes:  pkB64,
		PubKeyDigest: dB64,
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
