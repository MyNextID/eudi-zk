package signer_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/mynextid/cades/signer"
)

func TestCAdES(t *testing.T) {

	// Create output directory if it doesn't exist
	outputDir := "output"
	if err := createDir(outputDir); err != nil {
		panic(err)
	}

	sig, err := signer.NewTestSigner()
	if err != nil {
		t.Fatalf("failed to create a new signer: %v", err)
	}

	// data to sign
	data := []byte("This is the content to be signed with CAdES-BES")

	signature, err := sig.Sign(rand.Reader, data, signer.CAdESOpts{Detached: false})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	signatureDetached, err := sig.Sign(rand.Reader, data, signer.CAdESOpts{Detached: true})
	if err != nil {
		t.Fatalf("failed to sign (detached): %v", err)
	}

	// Save as .p7m file (enveloped signature format)
	err = os.WriteFile(filepath.Join(outputDir, "signature.p7m"), signature, 0644)
	if err != nil {
		panic(err)
	}

	// Save the original data
	err = os.WriteFile(filepath.Join(outputDir, "payload-detached.txt"), data, 0644)
	if err != nil {
		panic(err)
	}

	// Save as .p7m file (detached signature format)
	err = os.WriteFile(filepath.Join(outputDir, "signature-detached.p7m"), signatureDetached, 0644)
	if err != nil {
		panic(err)
	}
}

// newOutputDir checks if the output directory exists, creates it if not
func createDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}
