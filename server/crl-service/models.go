package crlservice

import (
	"math/big"
	"time"
)

// ============================================================================
// Core Domain Models
// ============================================================================

// CertificateInfo represents a registered certificate in the system
type CertificateInfo struct {
	SerialNumber *big.Int  `json:"serialNumber"` // base64url encoded in JSON
	CRLId        string    `json:"crlId"`
	RegisteredAt time.Time `json:"registeredAt"`
}

// Revocation represents a certificate revocation entry
type Revocation struct {
	SerialNumber     *big.Int  `json:"serialNumber"`
	RevocationTime   time.Time `json:"revocationTime"`
	RevocationReason int       `json:"revocationReason"`
}

// CRLInfo represents metadata about a CRL
type CRLInfo struct {
	CRLId        string    `json:"crlId"`
	EntryCount   int       `json:"entryCount"`
	RevokedCount int       `json:"revokedCount"`
	LastUpdate   time.Time `json:"lastUpdate"`
	NextUpdate   time.Time `json:"nextUpdate"`
}

// MiniCRLRange represents a partition range for mini CRLs
// The range covers (SerialNumberLow, SerialNumberHigh) - exclusive boundaries
type MiniCRLRange struct {
	CRLId            string   `json:"crlId"` // Deterministic ID based on range
	SerialNumberLow  *big.Int `json:"serialNumberLow"`
	SerialNumberHigh *big.Int `json:"serialNumberHigh"`
	RevokedCount     int      `json:"revokedCount"`
}

// CRLCacheEntry represents a cached CRL with metadata
type CRLCacheEntry struct {
	CRL        []byte
	CreatedAt  time.Time
	NextUpdate time.Time
	ETag       string
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

// POST /credential-ids
type registerCredentialIDRequest struct {
	SerialNumber string `json:"serialNumber"`
	CRLId        string `json:"crlId,omitempty"`
}

// RegisterCredentialIDResponse is the credential registration response
type RegisterCredentialIDResponse struct {
	CRLId string `json:"crlId"`
}

// ListCredentialsResponseElement represents a credential in the list
type ListCredentialsResponseElement struct {
	Name     string           `json:"name"`
	CertInfo *CertificateInfo `json:"certInfo"`
}

// ListCRLResponse represents a CRL in the list
type ListCRLResponse struct {
	Name string `json:"name"`
}

// RevokeCertificatesRequest is the input for POST /crl/{crl-id}/revoke
type RevokeCertificatesRequest struct {
	SerialNumbers    []string   `json:"serialNumbers"` // base64url encoded
	RevocationTime   *time.Time `json:"revocationTime,omitempty"`
	RevocationReason *int       `json:"revocationReason,omitempty"`
}

// RevokeCertificatesResponse is the output for POST /crl/{crl-id}/revoke
type RevokeCertificatesResponse struct {
	Success      []string          `json:"success"`
	Failed       []RevocationError `json:"failed,omitempty"`
	TotalRevoked int               `json:"totalRevoked"`
}

// RevocationError represents a failed revocation attempt
type RevocationError struct {
	SerialNumber string `json:"serialNumber"`
	Error        string `json:"error"`
}

// ListMiniCRLsResponse is the output for GET /crl/{crl-id}/mini-crls
type ListMiniCRLsResponse struct {
	CRLId      string         `json:"crlId"`
	MiniCRLs   []MiniCRLRange `json:"miniCrls"`
	TotalCount int            `json:"totalCount"`
}
