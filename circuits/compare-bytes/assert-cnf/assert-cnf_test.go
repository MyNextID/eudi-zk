package assertcnf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mynextid/eudi-zk/circuits"
	assertcnf "github.com/mynextid/eudi-zk/circuits/compare-bytes/assert-cnf"
)

func TestAssertCnfAPI(t *testing.T) {
	saveExamplePayload := true
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
	pubKeyBytesDigestHex := hex.EncodeToString(pubKeyBytesDigest[:])

	// Create JWS protected
	protected := map[string]any{
		"alg": "ES256",
		"typ": "JOSE+JSON",
		"cnf": map[string]string{
			"kid": pubKeyBytesDigestHex,
		},
	}
	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("Failed to marshal header: %v", err)
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)

	// Create JWS header
	cnf := map[string]any{
		"cnf": map[string]string{
			"kid": pubKeyBytesDigestHex,
		},
	}

	zkc, err := circuits.Compile(assertcnf.Info)
	if err != nil {
		t.Fatalf("zk circuit compilation failed: %v", err)
	}

	pvtIn := assertcnf.PrivateInput{
		ProtectedHeader: protectedB64,
		CnfClaim:        cnf,
	}
	pvtInBuf, err := json.Marshal(pvtIn)
	if err != nil {
		t.Fatalf("failed to marshal pvt input: %v", err)
	}
	pubIn := assertcnf.PublicInput{
		PublicKeyDigestHex: pubKeyBytesDigestHex,
	}
	pubInBuf, err := json.Marshal(pubIn)
	if err != nil {
		t.Fatalf("failed to marshal pub input: %v", err)
	}

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
