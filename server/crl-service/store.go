package crlservice

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// Store Implementation
// ============================================================================

// Store provides thread-safe in-memory storage for certificates and revocations
type Store struct {
	mu sync.RWMutex

	// certificates indexed by base64url encoded serial number
	certificates map[string]*CertificateInfo

	// revocations indexed by CRL ID, then by base64url encoded serial number
	revocations map[string]map[string]*Revocation

	// serial numbers grouped by CRL ID (sorted in ascending order)
	serialsByCRL map[string][]*big.Int

	// CRL cache indexed by CRL ID
	crlCache map[string]*CRLCacheEntry

	// Domain-specific CRL cache indexed by "crlId:domain"
	domainCRLCache map[string]*CRLCacheEntry

	// Mini CRL cache indexed by "crlId:miniCrlId"
	miniCRLCache map[string]*CRLCacheEntry

	// CRL number counter for each CRL ID
	crlNumbers map[string]int64

	// Last update time for each CRL ID
	crlLastUpdate map[string]time.Time
}

// NewStore creates a new in-memory store
func NewStore() *Store {
	return &Store{
		certificates:   make(map[string]*CertificateInfo),
		revocations:    make(map[string]map[string]*Revocation),
		serialsByCRL:   make(map[string][]*big.Int),
		crlCache:       make(map[string]*CRLCacheEntry),
		domainCRLCache: make(map[string]*CRLCacheEntry),
		miniCRLCache:   make(map[string]*CRLCacheEntry),
		crlNumbers:     make(map[string]int64),
		crlLastUpdate:  make(map[string]time.Time),
	}
}

// CertificateExists checks if a certificate with the given serial number exists
func (s *Store) CertificateExists(serialNumber string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.certificates[serialNumber]
	return exists
}

// AddCertificate adds a new certificate to the store
func (s *Store) AddCertificate(cert *CertificateInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Use base64url encoded serial number as key
	serialStr := base64.RawURLEncoding.EncodeToString(cert.SerialNumber.Bytes())
	s.certificates[serialStr] = cert

	// Add to CRL's serial number list
	if _, exists := s.serialsByCRL[cert.CRLId]; !exists {
		s.serialsByCRL[cert.CRLId] = []*big.Int{}
	}
	s.serialsByCRL[cert.CRLId] = append(s.serialsByCRL[cert.CRLId], cert.SerialNumber)

	// Keep the list sorted
	sort.Slice(s.serialsByCRL[cert.CRLId], func(i, j int) bool {
		return s.serialsByCRL[cert.CRLId][i].Cmp(s.serialsByCRL[cert.CRLId][j]) < 0
	})

	// Update last update time
	s.crlLastUpdate[cert.CRLId] = time.Now()

	return nil
}

// GetCertificate retrieves a certificate info by serial number
func (s *Store) GetCertificate(serialNumber string) (*CertificateInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, exists := s.certificates[serialNumber]
	if !exists {
		return nil, ErrCertificateNotFound
	}
	return cert, nil
}

// ListCRLs returns all CRL IDs
func (s *Store) ListCRLs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	crls := make([]string, 0, len(s.serialsByCRL))
	for crlID := range s.serialsByCRL {
		crls = append(crls, crlID)
	}
	sort.Strings(crls)
	return crls
}

// GetSerialNumbersByCRL returns all serial numbers for a CRL
func (s *Store) GetSerialNumbersByCRL(crlID string) []*big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	serials := s.serialsByCRL[crlID]
	if serials == nil {
		return nil
	}
	// Return a copy to prevent external modification
	result := make([]*big.Int, len(serials))
	copy(result, serials)
	return result
}

// GetRevocationsByCRL returns all revocations for a CRL
func (s *Store) GetRevocationsByCRL(crlID string) []*Revocation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	revMap, exists := s.revocations[crlID]
	if !exists {
		return []*Revocation{}
	}

	revs := make([]*Revocation, 0, len(revMap))
	for _, rev := range revMap {
		revs = append(revs, rev)
	}
	return revs
}

// IsRevoked checks if a certificate is revoked
func (s *Store) IsRevoked(crlID, serialNumber string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	revMap, exists := s.revocations[crlID]
	if !exists {
		return false
	}
	_, revoked := revMap[serialNumber]
	return revoked
}

// AddRevocation adds a revocation entry
func (s *Store) AddRevocation(crlID, serialNumber string, rev *Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.revocations[crlID]; !exists {
		s.revocations[crlID] = make(map[string]*Revocation)
	}
	s.revocations[crlID][serialNumber] = rev
	s.crlLastUpdate[crlID] = time.Now()
	return nil
}

// InvalidateCRLCache invalidates the full CRL cache for a CRL ID
func (s *Store) InvalidateCRLCache(crlID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.crlCache, crlID)
}

// InvalidateDomainCRLCache invalidates all domain CRL caches for a CRL ID
func (s *Store) InvalidateDomainCRLCache(crlID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove all domain-specific caches for this CRL
	keysToDelete := make([]string, 0)
	for key := range s.domainCRLCache {
		if len(key) > len(crlID) && key[:len(crlID)] == crlID {
			keysToDelete = append(keysToDelete, key)
		}
	}
	for _, key := range keysToDelete {
		delete(s.domainCRLCache, key)
	}
}

// InvalidateMiniCRLCache invalidates all mini CRL caches for a CRL ID
func (s *Store) InvalidateMiniCRLCache(crlID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove all mini CRL caches for this CRL
	keysToDelete := make([]string, 0)
	for key := range s.miniCRLCache {
		if len(key) > len(crlID) && key[:len(crlID)] == crlID {
			keysToDelete = append(keysToDelete, key)
		}
	}
	for _, key := range keysToDelete {
		delete(s.miniCRLCache, key)
	}
}

// GetCachedCRL retrieves a cached full CRL
func (s *Store) GetCachedCRL(crlID string) *CRLCacheEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.crlCache[crlID]
}

// CacheCRL stores a full CRL in the cache
func (s *Store) CacheCRL(crlID string, crlDER []byte, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.crlCache[crlID] = &CRLCacheEntry{
		CRL:        crlDER,
		CreatedAt:  now,
		NextUpdate: now.Add(maxAge),
		ETag:       fmt.Sprintf(`"%x"`, crlDER[:min(16, len(crlDER))]),
	}
}

// GetCachedDomainCRL retrieves a cached domain-specific CRL
func (s *Store) GetCachedDomainCRL(cacheKey string) *CRLCacheEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domainCRLCache[cacheKey]
}

// CacheDomainCRL stores a domain-specific CRL in the cache
func (s *Store) CacheDomainCRL(cacheKey string, crlDER []byte, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.domainCRLCache[cacheKey] = &CRLCacheEntry{
		CRL:        crlDER,
		CreatedAt:  now,
		NextUpdate: now.Add(maxAge),
		ETag:       fmt.Sprintf(`"%x"`, crlDER[:min(16, len(crlDER))]),
	}
}

// GetCachedMiniCRL retrieves a cached mini CRL
func (s *Store) GetCachedMiniCRL(cacheKey string) *CRLCacheEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.miniCRLCache[cacheKey]
}

// CacheMiniCRL stores a mini CRL in the cache
func (s *Store) CacheMiniCRL(cacheKey string, crlDER []byte, maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.miniCRLCache[cacheKey] = &CRLCacheEntry{
		CRL:        crlDER,
		CreatedAt:  now,
		NextUpdate: now.Add(maxAge),
		ETag:       fmt.Sprintf(`"%x"`, crlDER[:min(16, len(crlDER))]),
	}
}

// GetNextCRLNumber increments and returns the CRL number for a CRL ID
func (s *Store) GetNextCRLNumber(crlID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.crlNumbers[crlID]++
	return s.crlNumbers[crlID]
}

// GetLastUpdate returns the last update time for a CRL
func (s *Store) GetLastUpdate(crlID string) time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if t, exists := s.crlLastUpdate[crlID]; exists {
		return t
	}
	return time.Now()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
