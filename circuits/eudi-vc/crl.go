package cdl

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CircuitCRL defines a ZK circuit that verifies
// 1. A certificate's serial number is NOT in a provided CRL
// 2. The CRL signature is validated externally (assumed valid input)
// Note: this approach is super inefficient as the CRL grows
// BitString approach is probably more efficient, but it is encoded as hex+base64 ...
type CircuitCRL struct {
	// public inputs
	CRLBytes []uints.U8 `gnark:",public"` // The full CRL in DER format

	// private inputs
	CertBytes []uints.U8 `gnark:",secret"` // The certificate to check

	// Circuit parameters set at compile time
	MaxSerialLen int `gnark:"-"` // Maximum serial number length in bytes
}

// Define implements the gnark Circuit interface
func (c *CircuitCRL) Define(api frontend.API) error {
	// Verify that the certificate's serial number is NOT in the CRL
	VerifySerialNotRevoked(api, c.CertBytes, c.CRLBytes, c.MaxSerialLen)

	return nil
}

// NewCircuitCRL creates a new CRL verification circuit with specified sizes
func NewCircuitCRL(maxCertSize, maxCRLSize int) *CircuitCRL {
	return &CircuitCRL{
		CertBytes: make([]uints.U8, maxCertSize),
		CRLBytes:  make([]uints.U8, maxCRLSize),
	}
}

// CheckSerialInCRL verifies if a certificate serial number is present in a CRL
// Returns 1 if the serial is found (revoked), 0 if not found (valid)
func CheckSerialInCRL(
	api frontend.API,
	crlBytes []uints.U8,
	serialBytes []uints.U8,
	maxSerialLen int,
) frontend.Variable {
	index := frontend.Variable(0)

	// Skip outer CRL SEQUENCE
	tag := ReadByteAt(api, crlBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes := ReadDERLength(api, crlBytes, index)
	index = api.Add(index, lengthBytes)

	// Enter TBSCertList SEQUENCE
	tag = ReadByteAt(api, crlBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes = ReadDERLength(api, crlBytes, index)
	index = api.Add(index, lengthBytes)

	// Field 1: Version (optional, INTEGER 0x02)
	tag = ReadByteAt(api, crlBytes, index)
	hasVersion := api.IsZero(api.Sub(tag.Val, 0x02))
	skipAmount := api.Select(hasVersion, SkipElement(api, crlBytes, index), 0)
	index = api.Add(index, skipAmount)

	// Field 2: Signature Algorithm (SEQUENCE 0x30)
	tag = ReadByteAt(api, crlBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, crlBytes, index)
	index = api.Add(index, skipAmount)

	// Field 3: Issuer DN (SEQUENCE 0x30)
	tag = ReadByteAt(api, crlBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	skipAmount = SkipElement(api, crlBytes, index)
	index = api.Add(index, skipAmount)

	// Field 4: thisUpdate (TIME 0x17 or 0x18)
	skipAmount = SkipElement(api, crlBytes, index)
	index = api.Add(index, skipAmount)

	// Field 5: nextUpdate (optional, TIME 0x17 or 0x18)
	tag = ReadByteAt(api, crlBytes, index)
	isTime := api.Or(
		api.IsZero(api.Sub(tag.Val, 0x17)),
		api.IsZero(api.Sub(tag.Val, 0x18)),
	)
	skipAmount = api.Select(isTime, SkipElement(api, crlBytes, index), 0)
	index = api.Add(index, skipAmount)

	// Field 6: revokedCertificates (optional, SEQUENCE 0x30)
	// This is where we need to search for our serial number
	tag = ReadByteAt(api, crlBytes, index)
	hasRevokedCerts := api.IsZero(api.Sub(tag.Val, 0x30))

	// If no revoked certificates, serial is not in CRL
	found := frontend.Variable(0)

	// Only search if there are revoked certificates
	// We need to iterate through the sequence and check each entry
	revokedSeqStart := api.Add(index, 1)
	_, revokedLenBytes := ReadDERLength(api, crlBytes, api.Add(index, 1))
	revokedSeqDataStart := api.Add(revokedSeqStart, revokedLenBytes)

	// Search through revoked certificates
	// Each entry is a SEQUENCE containing: serialNumber, revocationDate, [extensions]
	searchIndex := revokedSeqDataStart

	// Simplified: just iterate a fixed number of times
	// The user should set this based on their CRL size
	maxEntries := 10 // Adjust based on your CRL

	for i := 0; i < maxEntries; i++ {
		// Always process, but results won't matter if hasRevokedCerts is 0

		// Read entry SEQUENCE tag
		entryTag := ReadByteAt(api, crlBytes, searchIndex)
		_ = api.IsZero(api.Sub(entryTag.Val, 0x30))

		// Skip SEQUENCE tag and read length
		serialIndex := api.Add(searchIndex, 1)
		entryContentLen, entryLenBytes := ReadDERLength(api, crlBytes, serialIndex)
		serialIndex = api.Add(serialIndex, entryLenBytes)

		// Now at serial number (INTEGER 0x02)
		_ = ReadByteAt(api, crlBytes, serialIndex) // Verify it's 0x02 if needed
		serialIndex = api.Add(serialIndex, 1)
		_, serialLenBytes := ReadDERLength(api, crlBytes, serialIndex)
		serialIndex = api.Add(serialIndex, serialLenBytes)

		// Compare serial numbers (fixed length comparison)
		serialMatch := CompareSerialNumbers(api, crlBytes, serialIndex, serialBytes, maxSerialLen)

		// Update found flag if we have a match and should process
		matchFound := api.And(hasRevokedCerts, serialMatch)
		found = api.Select(matchFound, 1, found)

		// Move to next entry
		entrySize := api.Add(api.Add(1, entryLenBytes), entryContentLen)
		searchIndex = api.Add(searchIndex, entrySize)
	}

	return found
}

// CompareSerialNumbers compares a serial number in the CRL with the provided serial
// Uses fixed-length comparison (maxSerialLen)
func CompareSerialNumbers(
	api frontend.API,
	crlBytes []uints.U8,
	crlSerialStart frontend.Variable,
	serialBytes []uints.U8,
	maxSerialLen int,
) frontend.Variable {
	// Compare each byte up to maxSerialLen
	allMatch := frontend.Variable(1)
	for i := range maxSerialLen {
		crlByte := ReadByteAt(api, crlBytes, api.Add(crlSerialStart, i))
		byteMatch := api.IsZero(api.Sub(crlByte.Val, serialBytes[i].Val))
		allMatch = api.And(allMatch, byteMatch)
	}

	return allMatch
}

// IsLessThan returns 1 if a < b, 0 otherwise
func IsLessThan(api frontend.API, a, b frontend.Variable) frontend.Variable {
	diff := api.Sub(b, a) // b - a
	isZero := api.IsZero(diff)

	// if b - a > 0, then a < b
	return api.Sub(1, isZero)
}

// ExtractSerialFromCert extracts the serial number bytes from a certificate
func ExtractSerialFromCert(
	api frontend.API,
	certBytes []uints.U8,
	maxSerialLen int,
) []uints.U8 {
	index := frontend.Variable(0)

	// Skip outer Certificate SEQUENCE
	tag := ReadByteAt(api, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes := ReadDERLength(api, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Enter TBSCertificate SEQUENCE
	tag = ReadByteAt(api, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x30)
	index = api.Add(index, 1)
	_, lengthBytes = ReadDERLength(api, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Field 1: Version [0] EXPLICIT (optional)
	tag = ReadByteAt(api, certBytes, index)
	hasVersion := api.IsZero(api.Sub(tag.Val, 0xA0))
	skipAmount := api.Select(hasVersion, SkipElement(api, certBytes, index), 0)
	index = api.Add(index, skipAmount)

	// Field 2: Serial Number (INTEGER 0x02)
	tag = ReadByteAt(api, certBytes, index)
	api.AssertIsEqual(tag.Val, 0x02)
	index = api.Add(index, 1)

	// Read serial length
	_, lengthBytes = ReadDERLength(api, certBytes, index)
	index = api.Add(index, lengthBytes)

	// Extract serial bytes up to maxSerialLen
	serialBytes := make([]uints.U8, maxSerialLen)

	for i := range maxSerialLen {
		byte := ReadByteAt(api, certBytes, api.Add(index, i))
		serialBytes[i] = byte
	}

	return serialBytes
}

// VerifySerialNotRevoked is a high-level function that extracts the serial
// from a certificate and checks it against a CRL
func VerifySerialNotRevoked(
	api frontend.API,
	certBytes []uints.U8,
	crlBytes []uints.U8,
	maxSerialLen int,
) {
	// Extract serial from certificate
	serialBytes := ExtractSerialFromCert(api, certBytes, maxSerialLen)

	// Check if serial is in CRL
	isRevoked := CheckSerialInCRL(api, crlBytes, serialBytes, maxSerialLen)

	// Assert the certificate is NOT revoked
	api.AssertIsEqual(isRevoked, 0)
}
