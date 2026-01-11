package crlservice

import "time"

// Config holds service configuration parameters
type Config struct {
	// CRLValidityDuration is how long a CRL is valid
	CRLValidityDuration time.Duration

	// EnableCaching enables CRL caching
	EnableCaching bool

	// CacheMaxAge is how long CRLs are cached
	CacheMaxAge time.Duration
}

// DefaultConfig returns sensible defaults for the CRL service
func DefaultConfig() *Config {
	return &Config{
		CRLValidityDuration: 1 * time.Hour,
		EnableCaching:       true,
		CacheMaxAge:         1 * time.Hour,
	}
}
