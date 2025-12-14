package ccb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark/std/math/uints"
	ccb "github.com/mynextid/eudi-zk/circuits/compare-bytes"
	"github.com/mynextid/eudi-zk/common"
)

func TestCircuitCompareCnf(t *testing.T) {

	ccsPath := "compiled/circuit-cnf-v1.ccs"
	pkPath := "compiled/proving-cnf-v1.key"
	vkPath := "compiled/verifying-cnf-v1.key"

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

	// Create JWS protected
	protected := map[string]any{
		"alg": "ES256",
		"typ": "JOSE+JSON",
		"cnf": map[string]string{
			"kid": pubKeyBytesDigestHex,
		},
	}

	// Create JWS header
	cnf := map[string]any{
		"cnf": map[string]string{
			"kid": pubKeyBytesDigestHex,
		},
	}

	cnfJSON, err := json.Marshal(cnf)
	if err != nil {
		t.Fatalf("Failed to marshal header: %v", err)
	}

	cnfStr := strings.TrimPrefix(string(cnfJSON), "{")
	cnfStr = strings.TrimSuffix(cnfStr, "}")

	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("Failed to marshal header: %v", err)
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(protectedJSON)

	// Find where "cnf":" appears
	cnfStart := strings.Index(string(protectedJSON), cnfStr)
	if cnfStart == -1 {
		t.Fatal("cnf field not found in JSON")
	}
	// Length of the cnf variable
	cnfLen := len(cnfStr)
	cnfEnd := cnfStart + cnfLen

	cnfStartNew, cnfEndNew := common.B64Align(cnfStart, cnfEnd)

	cnfAligned := protectedJSON[cnfStartNew:cnfEndNew]
	fmt.Println(string(cnfJSON))
	fmt.Println(string(cnfAligned))

	cnfAlignedB64 := base64.RawURLEncoding.EncodeToString([]byte(cnfAligned))

	isSubset := strings.Contains(protectedB64, cnfAlignedB64)
	if !isSubset {
		t.Log(protectedB64)
		t.Log(cnfAlignedB64)
		t.Fatal("cnf is not a subset")
	}

	// get the public key position
	pubKeyIndex := strings.Index(string(cnfAligned), pubKeyBytesDigestHex)
	if cnfStart == -1 {
		t.Fatal("public key not found in JSON")
	}

	circuitTemplate := &ccb.CircuitCompareCnf{
		HeaderB64:       make([]uints.U8, len(protectedB64)),
		CnfB64:          make([]uints.U8, len(cnfAlignedB64)),
		PublicKeyDigest: make([]uints.U8, len(pubKeyBytesDigest)),
	}

	cnfB64Index := strings.Index(protectedB64, cnfAlignedB64)
	if cnfStart == -1 {
		t.Fatal("failed to get cnfB64 index")
	}

	fmt.Println("cnfAligned", string(cnfAligned))
	fmt.Println("pubkeyhexposition", pubKeyIndex)

	// Create witness assignment with actual values
	assignment := &ccb.CircuitCompareCnf{
		HeaderB64:         common.StringToU8Array(protectedB64),
		CnfB64:            common.StringToU8Array(cnfAlignedB64),
		CnfB64Position:    cnfB64Index,
		PubKeyHexPosition: pubKeyIndex,
		PublicKeyDigest:   common.BytesToU8Array(pubKeyBytesDigest[:]),
	}

	// == Init the circuit ==
	fmt.Println("\n--- Init the circuit ---")
	startCircuit := time.Now()

	ccs, pk, vk, err := common.InitCircuit(ccsPath, pkPath, vkPath, forceCompile, circuitTemplate)
	if err != nil {
		t.Fatalf("failed to initialize a circuit: %v", err)
	}

	circuitTime := time.Since(startCircuit)
	fmt.Printf("[OK] Circuit created/loaded successfully! (took %v)\n", circuitTime)

	// == Run the circuit ==
	common.TestCircuitSimple(assignment, ccs, pk, vk)

}
