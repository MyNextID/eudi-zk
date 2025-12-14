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
	"github.com/mynextid/eudi-zk/common"
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
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)
	pubKeyBytesDigestHex := hex.EncodeToString(pubKeyBytesDigest[:])
	pubKeyBytesDigestHexB64 := []byte(base64.RawURLEncoding.EncodeToString([]byte(pubKeyBytesDigestHex)))

	circuitTemplate := &ccb.CircuitB64Url{
		Bytes:    make([]uints.U8, len(pubKeyBytesDigest)),
		BytesB64: make([]uints.U8, len(pubKeyBytesDigestHexB64)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitB64Url{
		Bytes:    common.BytesToU8Array(pubKeyBytesDigest[:]),
		BytesB64: common.BytesToU8Array(pubKeyBytesDigestHexB64),
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)
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
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	pubKeyBytesHex := []byte(hex.EncodeToString(pubKeyBytes))

	circuitTemplate := &ccb.CircuitHex{
		Bytes:    make([]uints.U8, len(pubKeyBytes)),
		BytesHex: make([]uints.U8, len(pubKeyBytesHex)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitHex{
		Bytes:    common.BytesToU8Array(pubKeyBytes),
		BytesHex: common.BytesToU8Array(pubKeyBytesHex),
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)

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
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), signerKey.PublicKey.X, signerKey.PublicKey.Y)

	pubKeyBytesDigest := sha256.Sum256(pubKeyBytes)

	circuitTemplate := &ccb.CircuitPKDigest{

		SignerPubKeyBytes:  make([]uints.U8, len(pubKeyBytes)),
		SignerPubKeyDigest: make([]uints.U8, len(pubKeyBytesDigest)),
	}

	// Create witness assignment with actual values
	assignment := &ccb.CircuitPKDigest{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerPubKeyBytes:  common.BytesToU8Array(pubKeyBytes),
		SignerPubKeyDigest: common.BytesToU8Array(pubKeyBytesDigest[:]),
	}
	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)
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
	publicKeyXBytes := signerKey.PublicKey.X.Bytes()
	publicKeyYBytes := signerKey.PublicKey.Y.Bytes()

	circuitTemplate := &ccb.CircuitPK{

		SignerPubKeyXBytes: make([]uints.U8, len(publicKeyXBytes)),
		SignerPubKeyYBytes: make([]uints.U8, len(publicKeyYBytes)),
	}
	// Create witness assignment with actual values
	assignment := &ccb.CircuitPK{
		SignerPubKeyX:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.X),
		SignerPubKeyY:      emulated.ValueOf[Secp256r1Fp](signerKey.PublicKey.Y),
		SignerPubKeyXBytes: common.BytesToU8Array(publicKeyXBytes),
		SignerPubKeyYBytes: common.BytesToU8Array(publicKeyYBytes),
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)
}

func TestCompareBytes(t *testing.T) {
	ccsPath := "compiled/cb-circuit-v1.ccs"
	pkPath := "compiled/cb-proving-v1.key"
	vkPath := "compiled/cb-verifying-v1.key"

	forceCompile := true

	byteSize := 32

	randomBytes, err := common.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}
	randomBytes2, err := common.GenerateRandomBytes(byteSize)
	if err != nil {
		t.Error(err)
	}

	circuitTemplate := &ccb.Circuit{
		Bytes:    make([]uints.U8, byteSize),
		PubBytes: make([]uints.U8, byteSize),
	}

	// Create witness assignment with actual values
	assignment := &ccb.Circuit{
		// Private inputs
		Bytes: common.BytesToU8Array(randomBytes),
		// Public inputs
		PubBytes: common.BytesToU8Array(randomBytes),
	}
	_ = randomBytes2

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("✓ Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuit(assignment, ccs, pk, vk)

}
