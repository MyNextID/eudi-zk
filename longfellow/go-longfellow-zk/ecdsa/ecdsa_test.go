package ecdsa_test

import (
	"fmt"
	"testing"

	"github.com/mynextid/eudi-zk/longfellow/go-longfellow-zk/ecdsa"
)

// Temporary Workaround:
// CGO_LDFLAGS_ALLOW=".*" go test -v -test.fullpath=true -timeout 5m -run ^TestECDSA_C$ github.com/mynextid/eudi-zk/longfellow/go-longfellow-zk/ecdsa
// TODO: install the libraries to the standard location
// sudo cp ../../cpp/build/liblongfellow_wrapper.0.dylib /usr/local/lib/
// sudo ldconfig  # or update_dyld_shared_cache on macOS
func TestECDSA_C(t *testing.T) {
	circuitName := "validateECDSA"
	// Initialize circuit once at startup
	if err := ecdsa.InitCircuit(circuitName); err != nil {
		t.Fatalf("failed to initialize circuit: %v", err)
	}
	defer ecdsa.FreeCircuit(circuitName)

	fmt.Printf("[OK] Circuit %s initialized", circuitName)

	// Create a proof
	proof, err := ecdsa.CreateProof(
		circuitName,
		"0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c",
		"0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75",
		"0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		"0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671",
		"0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd40",
	)
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}

	fmt.Printf("[OK] Proof created (%d bytes)\n", proof.Size())
	fmt.Printf("  Proof hex (first 64 chars): %s...\n", proof.Hex()[:64])

	// Verify the proof
	valid, err := ecdsa.VerifyProof(
		circuitName,
		"0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c",
		"0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75",
		"0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		proof,
	)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}

	if valid {
		fmt.Println("[OK] Proof verified successfully!")
	} else {
		t.Fatal("[ERROR] Proof verification failed")
	}
}
