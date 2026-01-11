package crlservice

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// ============================================================================
// Router Setup
// ============================================================================

// RegisterRoutes registers all CRL routes with the Chi router
func RegisterRoutes(r chi.Router, handler *CRLHandler) {
	// Credential management
	r.Get("/", handler.HandleDiscovery)
	r.Post("/credential-ids", handler.HandleRegisterCredentialID)
	r.Get("/credentials-ids", handler.HandleListCredentials)
	r.Get("/credential-ids/{serialNumber}", handler.HandleGetCredential)

	// CRL operations
	r.Get("/crl", handler.HandleListCRLs)
	r.Get("/crl/{crlId}", handler.HandleGetCRL)
	r.Get("/crl/{crlId}/domains/{domain}", handler.HandleGetCRLForDomain)
	r.Get("/crl/{crlId}/info", handler.HandleGetCRLInfo)
	// r.Get("/crl/{crlId}/serial-numbers", handler.HandleListCRLSerialNumbers)

	// Revocation
	r.Post("/crl/{crlId}/revoke", handler.HandleRevoke)

	// Mini CRLs
	r.Get("/crl/{crlId}/mini-crls", handler.HandleListMiniCRLs)                    // Also handles ?serialNumber={sn}
	r.Get("/crl/{crlId}/mini-crls:lookup", handler.HandleGetMiniCRLBySerialNumber) // handles ?serialNumber={sn}
	r.Get("/crl/{crlId}/mini-crls/{miniCrlId}", handler.HandleGetMiniCRL)
}

// ============================================================================
// Middleware
// ============================================================================

// CacheControlMiddleware adds cache control headers
func CacheControlMiddleware(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache GET requests
			if r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/info") {
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
			}
			next.ServeHTTP(w, r)
		})
	}
}
