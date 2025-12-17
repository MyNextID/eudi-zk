package csv

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mynextid/eudi-zk/common"
)

// verifyPubKeyInCertificateSimplified searches for the public key X coordinate in the DER certificate. Note: this simplified version is insecure as it will try to match ANY public key in the certificate.
func (circuit *CircuitJWS) verifyPubKeyInCertificateSimplified(api frontend.API) error {
	/*
		Naive and insecure approach
		1. Find the 0x04 (uncompressed point indicator) in the certificate
		2. The public key X coordinate should appear immediately after
		3. Search through the entire DER certificate for this pattern

		DER structure for P-256 public key in certificate:
		... BIT STRING ... 0x04 [32 bytes of X] [32 bytes of Y] ...

		Note: this approach is fast, but we're not checking whether the public key is the subject's public key. For that, see the EUDI circuit where we validate the correct certificate path.
	*/

	// Convert public key X to bytes (32 bytes for P-256)
	pubKeyXBytes := common.EmulatedElementToBytes32(api, circuit.SignerPubKeyX)

	derLen := len(circuit.CertTBSDER)
	matchCount := frontend.Variable(0)

	// Search for the pattern: 0x04 followed by 32 bytes matching pubKeyX
	// We need at least 33 bytes: 1 (0x04) + 32 (X coordinate)
	if derLen < 33 {
		// Certificate too short, this will fail the assertion below
		api.AssertIsEqual(matchCount, 1)
		return nil
	}

	// Slide through the DER certificate
	for i := 0; i < derLen-32; i++ { // -32 to ensure we have room for X coordinate
		// Check if current byte is 0x04 (uncompressed point indicator)
		is04 := api.IsZero(api.Sub(circuit.CertTBSDER[i].Val, 0x04))

		// Check if the next 32 bytes match pubKeyX
		var xMatch frontend.Variable
		if i+32 < derLen {
			// Extract the slice for comparison
			certSlice := make([]uints.U8, 32)
			for j := 0; j < 32; j++ {
				certSlice[j] = circuit.CertTBSDER[i+1+j]
			}
			xMatch = common.IsEqualBytes(api, certSlice, pubKeyXBytes)
		} else {
			xMatch = 0
		}

		// If both conditions match (0x04 AND X coordinate matches), count it
		thisMatch := api.Mul(is04, xMatch)
		matchCount = api.Add(matchCount, thisMatch)
	}

	// Assert we found at least one match
	// matchCount should be >= 1, so (matchCount == 0) should be false
	isZero := api.IsZero(matchCount)
	api.AssertIsEqual(isZero, 0)
	return nil
}
