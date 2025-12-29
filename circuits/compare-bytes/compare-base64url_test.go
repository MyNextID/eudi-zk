package ccb_test

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
	"time"

	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/circuits"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/zkcore"
)

func TestCompareB64Url(t *testing.T) {
	// == Circuit data ==
	ccsPath := "compiled/cb-circuit-b64url-v1.ccs"
	pkPath := "compiled/cb-proving-b64url-v1.key"
	vkPath := "compiled/cb-verifying-b64url-v1.key"
	// true: recompile, false: load circuit if exists
	forceCompile := true

	// == Prepare the inputs ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)

	pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)
	pubKeyBytesDigestB64 := []byte(base64.RawURLEncoding.EncodeToString([]byte(pubKeyBytesDigest[:])))

	circuitTemplate := &ccb.CBB64UrlCircuit{
		SecretBytes: make([]uints.U8, len(pubKeyBytesDigest)),
		PublicBytes: make([]uints.U8, len(pubKeyBytesDigestB64)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CBB64UrlCircuit{
		SecretBytes: zkcore.BytesToU8Array(pubKeyBytesDigest[:]),
		PublicBytes: zkcore.BytesToU8Array(pubKeyBytesDigestB64),
	}

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

func TestCompareB64(t *testing.T) {

	// TODO: the limit is set within the circuit but we don't check it explicitly
	byteSize := 64

	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytesB64 := make([]byte, base64.RawURLEncoding.EncodedLen(byteSize))
	base64.RawURLEncoding.Encode(randomBytesB64, randomBytes)

	zkc, err := circuits.Compile(ccb.CBB64UrlInfo)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	// Create witness assignment with actual values
	assignment := &ccb.CBB64UrlCircuit{
		// Private inputs
		SecretBytes: zkcore.BytesToU8Array(randomBytes),
		// Public inputs
		PublicBytes: zkcore.BytesToU8Array(randomBytesB64),
	}

	proof, err := zkc.Prove(assignment)
	if err != nil {
		t.Fatalf("failed to create a proof: %v", err)
	}

	// Create public witness assignment with actual values
	assignmentPublic := &ccb.CBB64UrlCircuit{
		// Public inputs
		PublicBytes: zkcore.BytesToU8Array(randomBytesB64),
	}

	err = zkc.Verify(assignmentPublic, proof)
	if err != nil {
		t.Fatalf("failed to verify a proof: %v", err)
	}

}

func TestCompareB64API(t *testing.T) {

	// TODO: the limit is set within the circuit but we don't check it explicitly
	byteSize := 64
	saveExamplePayload := true

	// Generate inputs
	randomBytes, err := zkcore.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	zkc, err := circuits.Compile(ccb.CBB64UrlInfo)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	randomBytesB64 := base64.RawURLEncoding.EncodeToString(randomBytes)

	pvtIn := ccb.CBB64UrlPrivateInput{
		Bytes: randomBytesB64,
	}
	pvtInBuf, _ := json.Marshal(pvtIn)
	pubIn := ccb.CBB64UrlPublicInput{
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
