package crlservice

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Identifier and serial number size constants
const (
	CRLIDSize        = 10 // size of the CRL ID in bytes
	SerialNumberSize = 10 // size of the Domain Bound ID in bytes
)

// ============================================================================
// CRL Service Implementation
// ============================================================================

// CRLService provides certificate revocation list operations
type CRLService struct {
	store  *Store
	config *Config
	ca     *CAManager
}

// NewCRLService creates a new CRL service instance
func NewCRLService(store *Store, config *Config, ca *CAManager) *CRLService {
	return &CRLService{
		store:  store,
		config: config,
		ca:     ca,
	}
}

// ============================================================================
// Core Service Functions
// ============================================================================

// RegisterCredentialID registers a new credential and links it to a crlID
// POST /credential-ids
func (cs *CRLService) RegisterCredentialID(serialNumber, crlID string) (*RegisterCredentialIDResponse, error) {
	snBytes, err := base64.RawURLEncoding.DecodeString(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("serial number must be base64url encoded. Decoding failed: %w", err)
	}
	serial := new(big.Int).SetBytes(snBytes)

	// if crlID is not provided, create a new one
	if crlID == "" {
		crlID, err = cs.generateCRLID()
		if err != nil {
			return nil, err
		}
	}

	if cs.store.CertificateExists(serialNumber) {
		return nil, errors.New("certificate with this serial number already exists")
	}

	certificate := &CertificateInfo{
		SerialNumber: serial,
		CRLId:        crlID,
		RegisteredAt: time.Now(),
	}

	if err := cs.store.AddCertificate(certificate); err != nil {
		return nil, err
	}

	cs.store.InvalidateCRLCache(crlID)

	return &RegisterCredentialIDResponse{
		CRLId: crlID,
	}, nil
}

// ListCredentials returns all registered credentials
// GET /credential-ids
func (cs *CRLService) ListCredentials() ([]ListCredentialsResponseElement, error) {
	cs.store.mu.RLock()
	defer cs.store.mu.RUnlock()

	certs := make([]ListCredentialsResponseElement, 0, len(cs.store.certificates))

	for sn, c := range cs.store.certificates {
		certs = append(certs, ListCredentialsResponseElement{
			Name:     fmt.Sprintf("/credential-ids/%s", sn),
			CertInfo: c,
		})
	}

	return certs, nil
}

// GetCredential retrieves a specific credential by serial number
// GET /credential-ids/{serialNumber}
func (cs *CRLService) GetCredential(serialNumber string) (*CertificateInfo, error) {
	return cs.store.GetCertificate(serialNumber)
}

// ListCRL returns all registered CRL IDs
// GET /crl
func (cs *CRLService) ListCRL() []ListCRLResponse {
	crlList := cs.store.ListCRLs()
	r := make([]ListCRLResponse, 0, len(crlList))
	for _, crlID := range crlList {
		r = append(r, ListCRLResponse{Name: fmt.Sprintf("/crl/%s", crlID)})
	}
	return r
}

// GetCRL returns the complete CRL for a given CRL ID in DER format
// GET /crl/{crl-id}
func (cs *CRLService) GetCRL(crlID string) ([]byte, error) {
	if cs.config.EnableCaching {
		if cached := cs.store.GetCachedCRL(crlID); cached != nil {
			if time.Now().Before(cached.NextUpdate) {
				return cached.CRL, nil
			}
		}
	}

	crlDER, err := cs.generateFullCRL(crlID)
	if err != nil {
		return nil, err
	}

	if cs.config.EnableCaching {
		cs.store.CacheCRL(crlID, crlDER, cs.config.CacheMaxAge)
	}

	return crlDER, nil
}

// GetCRLInfo returns metadata about a CRL
// GET /crl/{crl-id}/info
func (cs *CRLService) GetCRLInfo(crlID string) (*CRLInfo, error) {
	serials := cs.store.GetSerialNumbersByCRL(crlID)
	if serials == nil {
		return nil, ErrCRLNotFound
	}

	revocations := cs.store.GetRevocationsByCRL(crlID)
	lastUpdate := cs.store.GetLastUpdate(crlID)

	info := &CRLInfo{
		CRLId:        crlID,
		EntryCount:   len(serials),
		RevokedCount: len(revocations),
		LastUpdate:   lastUpdate,
		NextUpdate:   lastUpdate.Add(cs.config.CRLValidityDuration),
	}

	return info, nil
}

// ListCRLSerialNumbers returns all serial numbers for a CRL
// GET /crl/{crl-id}/serial-numbers
func (cs *CRLService) ListCRLSerialNumbers(crlID string) ([]string, error) {
	serials := cs.store.GetSerialNumbersByCRL(crlID)
	if serials == nil {
		return nil, ErrCRLNotFound
	}

	result := make([]string, len(serials))
	for i, serial := range serials {
		result[i] = base64.RawURLEncoding.EncodeToString(serial.Bytes())
	}
	return result, nil
}

// Revoke revokes one or more certificates
// POST /crl/{crl-id}/revoke
func (cs *CRLService) Revoke(crlID string, req *RevokeCertificatesRequest) (*RevokeCertificatesResponse, error) {
	if len(req.SerialNumbers) == 0 {
		return nil, errors.New("no serial numbers provided")
	}

	revocationTime := time.Now()
	if req.RevocationTime != nil {
		revocationTime = *req.RevocationTime
	}

	revocationReason := 0
	if req.RevocationReason != nil {
		revocationReason = *req.RevocationReason
	}

	var successList []string
	var failedList []RevocationError

	for _, serialStr := range req.SerialNumbers {
		buf, err := base64.RawURLEncoding.DecodeString(serialStr)
		if err != nil {
			failedList = append(failedList, RevocationError{
				SerialNumber: serialStr,
				Error:        fmt.Sprintf("serial number must be base64url encoded. Decoding failed: %v", err),
			})
			continue
		}
		serial := new(big.Int).SetBytes(buf)

		cert, err := cs.store.GetCertificate(serialStr)
		if err != nil || cert == nil {
			failedList = append(failedList, RevocationError{
				SerialNumber: serialStr,
				Error:        "certificate not found",
			})
			continue
		}

		if cert.CRLId != crlID {
			failedList = append(failedList, RevocationError{
				SerialNumber: serialStr,
				Error:        "certificate not in this CRL",
			})
			continue
		}

		if cs.store.IsRevoked(crlID, serialStr) {
			failedList = append(failedList, RevocationError{
				SerialNumber: serialStr,
				Error:        "already revoked",
			})
			continue
		}

		revocation := &Revocation{
			SerialNumber:     serial,
			RevocationTime:   revocationTime,
			RevocationReason: revocationReason,
		}

		if err := cs.store.AddRevocation(crlID, serialStr, revocation); err != nil {
			failedList = append(failedList, RevocationError{
				SerialNumber: serialStr,
				Error:        err.Error(),
			})
			continue
		}

		successList = append(successList, serialStr)
	}

	cs.store.InvalidateCRLCache(crlID)
	cs.store.InvalidateDomainCRLCache(crlID)
	cs.store.InvalidateMiniCRLCache(crlID)

	return &RevokeCertificatesResponse{
		Success:      successList,
		Failed:       failedList,
		TotalRevoked: len(successList),
	}, nil
}

// GetDBCRL returns a domain-bound CRL
// GET /crl/{crl-id}/domains/{domain}
func (cs *CRLService) GetDBCRL(crlID, domain string) ([]byte, error) {
	if domain == "" {
		return nil, errors.New("domain parameter is required")
	}

	cacheKey := crlID + ":" + domain

	if cs.config.EnableCaching {
		if cached := cs.store.GetCachedDomainCRL(cacheKey); cached != nil {
			if time.Now().Before(cached.NextUpdate) {
				return cached.CRL, nil
			}
		}
	}

	crlDER, err := cs.generateDomainCRL(crlID, domain)
	if err != nil {
		return nil, err
	}

	if cs.config.EnableCaching {
		cs.store.CacheDomainCRL(cacheKey, crlDER, cs.config.CacheMaxAge)
	}

	return crlDER, nil
}

// ListMiniCRL returns all mini CRL ranges for a CRL
// GET /crl/{crl-id}/mini-crls
func (cs *CRLService) ListMiniCRL(crlID string) (*ListMiniCRLsResponse, error) {
	serials := cs.store.GetSerialNumbersByCRL(crlID)
	if serials == nil {
		return nil, ErrCRLNotFound
	}

	ranges := cs.calculateMiniCRLRanges(crlID, serials)

	return &ListMiniCRLsResponse{
		CRLId:      crlID,
		MiniCRLs:   ranges,
		TotalCount: len(ranges),
	}, nil
}

// GetMiniCRLByID returns a mini CRL by its ID
// GET /crl/{crl-id}/mini-crls/{mini-crl-id}
func (cs *CRLService) GetMiniCRLByID(crlID, miniCrlID string) ([]byte, error) {
	serials := cs.store.GetSerialNumbersByCRL(crlID)
	if serials == nil {
		return nil, ErrCRLNotFound
	}

	ranges := cs.calculateMiniCRLRanges(crlID, serials)

	// Find the range matching the mini CRL ID
	var targetRange *MiniCRLRange
	for i := range ranges {
		if ranges[i].CRLId == miniCrlID {
			targetRange = &ranges[i]
			break
		}
	}

	if targetRange == nil {
		return nil, fmt.Errorf("mini CRL with ID %s not found", miniCrlID)
	}

	miniCRLKey := crlID + ":" + miniCrlID

	if cs.config.EnableCaching {
		if cached := cs.store.GetCachedMiniCRL(miniCRLKey); cached != nil {
			if time.Now().Before(cached.NextUpdate) {
				return cached.CRL, nil
			}
		}
	}

	crlDER, err := cs.generateMiniCRL(crlID, []*big.Int{targetRange.SerialNumberLow, targetRange.SerialNumberHigh})
	if err != nil {
		return nil, err
	}

	if cs.config.EnableCaching {
		cs.store.CacheMiniCRL(miniCRLKey, crlDER, cs.config.CacheMaxAge)
	}

	return crlDER, nil
}

// GetMiniCRLBySerialNumber returns the mini CRL containing a specific serial number
// GET /crl/{crl-id}/mini-crls?serialNumber={serialNumber}
func (cs *CRLService) GetMiniCRLBySerialNumber(crlID, serialNumber string) ([]byte, error) {
	snBytes, err := base64.RawURLEncoding.DecodeString(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("serial number must be base64url encoded. Failed to decode: %w", err)
	}
	serial := new(big.Int).SetBytes(snBytes)

	serials := cs.store.GetSerialNumbersByCRL(crlID)
	if serials == nil {
		return nil, ErrCRLNotFound
	}

	// Build the extended serial number list with 0 and max
	snList := make([]*big.Int, 0, len(serials)+2)
	snList = append(snList, big.NewInt(0))
	snList = append(snList, serials...)

	maxBytes := make([]byte, SerialNumberSize)
	for i := range maxBytes {
		maxBytes[i] = 0xFF
	}
	maxSN := new(big.Int).SetBytes(maxBytes)
	snList = append(snList, maxSN)

	// Find the range containing the serial number
	var snLow, snHigh *big.Int
	found := false

	for i := 0; i < len(snList)-1; i++ {
		// Check if serial is in the range (snList[i], snList[i+1])
		if serial.Cmp(snList[i]) > 0 && serial.Cmp(snList[i+1]) < 0 {
			snLow = snList[i]
			snHigh = snList[i+1]
			found = true
			break
		}
		// Check if serial equals a boundary (it's registered)
		if serial.Cmp(snList[i]) == 0 {
			// Serial is at lower boundary
			if i > 0 {
				snLow = snList[i-1]
				snHigh = snList[i]
			} else {
				snLow = snList[i]
				snHigh = snList[i+1]
			}
			found = true
			break
		}
	}

	if !found {
		return nil, ErrSerialNotInRange
	}

	miniCRLID := generateMiniCRLID(snLow, snHigh)
	miniCRLKey := crlID + ":" + miniCRLID

	if cs.config.EnableCaching {
		if cached := cs.store.GetCachedMiniCRL(miniCRLKey); cached != nil {
			if time.Now().Before(cached.NextUpdate) {
				return cached.CRL, nil
			}
		}
	}

	crlDER, err := cs.generateMiniCRL(crlID, []*big.Int{snLow, snHigh})
	if err != nil {
		return nil, err
	}

	if cs.config.EnableCaching {
		cs.store.CacheMiniCRL(miniCRLKey, crlDER, cs.config.CacheMaxAge)
	}

	return crlDER, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func (cs *CRLService) generateCRLID() (string, error) {
	buf := make([]byte, CRLIDSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to create CRL ID: %w", err)
	}
	return fmt.Sprintf("crl:%s", hex.EncodeToString(buf)), nil
}

// generateFullCRL creates a new CRL with all revocation entries
func (cs *CRLService) generateFullCRL(crlID string) ([]byte, error) {
	revocations := cs.store.GetRevocationsByCRL(crlID)

	revokedCerts := make([]pkix.RevokedCertificate, 0, len(revocations))
	for _, rev := range revocations {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   rev.SerialNumber,
			RevocationTime: rev.RevocationTime,
		})
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:              big.NewInt(cs.store.GetNextCRLNumber(crlID)),
		ThisUpdate:          now,
		NextUpdate:          now.Add(cs.config.CRLValidityDuration),
		RevokedCertificates: revokedCerts,
	}

	crlDER, err := cs.ca.SignCRL(template)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CRL: %w", err)
	}
	return crlDER, nil
}

// generateDomainCRL creates a domain-bound CRL with hashed serial numbers
func (cs *CRLService) generateDomainCRL(crlID, domain string) ([]byte, error) {
	revocations := cs.store.GetRevocationsByCRL(crlID)

	revokedCerts := make([]pkix.RevokedCertificate, 0, len(revocations))
	for _, rev := range revocations {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   domainBoundSerialNumber(rev.SerialNumber, domain),
			RevocationTime: rev.RevocationTime,
		})
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:              big.NewInt(cs.store.GetNextCRLNumber(crlID)),
		ThisUpdate:          now,
		NextUpdate:          now.Add(cs.config.CRLValidityDuration),
		RevokedCertificates: revokedCerts,
	}

	crlDER, err := cs.ca.SignCRL(template)
	if err != nil {
		return nil, fmt.Errorf("failed to sign domain CRL: %w", err)
	}
	return crlDER, nil
}

// domainBoundSerialNumber creates a domain-bound serial number by hashing serial number || domain
func domainBoundSerialNumber(sn *big.Int, domain string) *big.Int {
	digest := sha256.Sum256(append(sn.Bytes(), []byte(domain)...))
	dbSn := new(big.Int).SetBytes(digest[:SerialNumberSize])
	return dbSn
}

// calculateMiniCRLRanges creates ranges between registered serial numbers
func (cs *CRLService) calculateMiniCRLRanges(crlID string, serials []*big.Int) []MiniCRLRange {
	if len(serials) == 0 {
		return []MiniCRLRange{}
	}

	// Build extended list: [0, serial1, serial2, ..., serialN, max]
	snList := make([]*big.Int, 0, len(serials)+2)
	snList = append(snList, big.NewInt(0))
	snList = append(snList, serials...)

	maxBytes := make([]byte, SerialNumberSize)
	for i := range maxBytes {
		maxBytes[i] = 0xFF
	}
	maxSN := new(big.Int).SetBytes(maxBytes)
	snList = append(snList, maxSN)

	// Create ranges between consecutive elements
	ranges := make([]MiniCRLRange, 0, len(snList)-1)
	revocations := cs.store.GetRevocationsByCRL(crlID)

	for i := 0; i < len(snList)-1; i++ {
		snLow := snList[i]
		snHigh := snList[i+1]

		// Count revoked certificates in this range
		revokedCount := 0
		for _, rev := range revocations {
			if rev.SerialNumber.Cmp(snLow) >= 0 && rev.SerialNumber.Cmp(snHigh) <= 0 {
				revokedCount++
			}
		}

		ranges = append(ranges, MiniCRLRange{
			CRLId:            generateMiniCRLID(snLow, snHigh),
			SerialNumberLow:  snLow,
			SerialNumberHigh: snHigh,
			RevokedCount:     revokedCount,
		})
	}

	return ranges
}

// generateMiniCRLID creates a deterministic ID for a mini CRL range
func generateMiniCRLID(snLow, snHigh *big.Int) string {
	data := append(snLow.Bytes(), snHigh.Bytes()...)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("minicrl:%s", hex.EncodeToString(hash[:8]))
}

// generateMiniCRL creates a CRL for a specific serial number range
func (cs *CRLService) generateMiniCRL(crlID string, serialNumberRange []*big.Int) ([]byte, error) {
	if len(serialNumberRange) != 2 {
		return nil, errors.New("serial number range must contain exactly 2 elements (low and high)")
	}

	allRevocations := cs.store.GetRevocationsByCRL(crlID)
	snLow := serialNumberRange[0]
	snHigh := serialNumberRange[1]

	revokedCerts := make([]pkix.RevokedCertificate, 0)
	for _, rev := range allRevocations {
		if rev.SerialNumber.Cmp(snLow) >= 0 && rev.SerialNumber.Cmp(snHigh) <= 0 {
			revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
				SerialNumber:   rev.SerialNumber,
				RevocationTime: rev.RevocationTime,
			})
		}
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:              big.NewInt(cs.store.GetNextCRLNumber(crlID)),
		ThisUpdate:          now,
		NextUpdate:          now.Add(cs.config.CRLValidityDuration),
		RevokedCertificates: revokedCerts,
	}

	crlDER, err := cs.ca.SignCRL(template)
	if err != nil {
		return nil, fmt.Errorf("failed to sign mini CRL: %w", err)
	}
	return crlDER, nil
}
