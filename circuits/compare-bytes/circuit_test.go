package ccb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/zkcore"
)

// Define Secp256r1 field parameters
type Secp256r1Fp = emulated.P256Fp
type Secp256r1Fr = emulated.P256Fr

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
		Bytes:    make([]uints.U8, len(pubKeyBytesDigest)),
		BytesB64: make([]uints.U8, len(pubKeyBytesDigestB64)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CBB64UrlCircuit{
		Bytes:    zkcore.BytesToU8Array(pubKeyBytesDigest[:]),
		BytesB64: zkcore.BytesToU8Array(pubKeyBytesDigestB64),
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

func TestCompareHex(t *testing.T) {
	ccsPath := "compiled/cb-circuit-hex-v1.ccs"
	pkPath := "compiled/cb-proving-hex-v1.key"
	vkPath := "compiled/cb-verifying-hex-v1.key"

	forceCompile := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)

	pubKeyBytesHex := []byte(hex.EncodeToString(pubKeyBytes))

	circuitTemplate := &ccb.CircuitHex{
		Bytes:    make([]uints.U8, len(pubKeyBytes)),
		BytesHex: make([]uints.U8, len(pubKeyBytesHex)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitHex{
		Bytes:    zkcore.BytesToU8Array(pubKeyBytes),
		BytesHex: zkcore.BytesToU8Array(pubKeyBytesHex),
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

func TestCompareDigestPubKeys(t *testing.T) {
	ccsPath := "compiled/cb-circuit-digest-pub-key-v1.ccs"
	pkPath := "compiled/cb-proving-digest-pub-key-v1.key"
	vkPath := "compiled/cb-verifying-digest-pub-key-v1.key"

	forceCompile := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.X, signerKey.Y)

	pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)

	circuitTemplate := &ccb.CircuitPKDigest{

		SignerPubKeyBytes:  make([]uints.U8, len(pubKeyBytes)),
		SignerPubKeyDigest: make([]uints.U8, len(pubKeyBytesDigest)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitPKDigest{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](signerKey.X),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](signerKey.Y),
		SignerPubKeyBytes:  zkcore.BytesToU8Array(pubKeyBytes),
		SignerPubKeyDigest: zkcore.BytesToU8Array(pubKeyBytesDigest[:]),
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

func TestComparePublicKeys(t *testing.T) {
	ccsPath := "compiled/cb-circuit-pub-key-v1.ccs"
	pkPath := "compiled/cb-proving-pub-key-v1.key"
	vkPath := "compiled/cb-verifying-pub-key-v1.key"

	forceCompile := true

	// == create dummy data ==
	// Generate ES256 (P-256) key pair
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate key: %v", err))
	}

	// Properly encode the public key in uncompressed format
	// This ensures X and Y are always 32 bytes each
	publicKeyXBytes := signerKey.X.Bytes()
	publicKeyYBytes := signerKey.Y.Bytes()

	circuitTemplate := &ccb.CircuitPK{

		SignerPubKeyXBytes: make([]uints.U8, len(publicKeyXBytes)),
		SignerPubKeyYBytes: make([]uints.U8, len(publicKeyYBytes)),
	}
	// Create witness assignment with actual values
	assignment := &ccb.CircuitPK{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](signerKey.X),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](signerKey.Y),
		SignerPubKeyXBytes: zkcore.BytesToU8Array(publicKeyXBytes),
		SignerPubKeyYBytes: zkcore.BytesToU8Array(publicKeyYBytes),
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
