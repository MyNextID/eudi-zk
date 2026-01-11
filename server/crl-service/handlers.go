package crlservice

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mynextid/eudi-zk/server/discovery"
)

// ============================================================================
// HTTP Handlers
// ============================================================================

// CRLHandler provides HTTP handlers for CRL operations
type CRLHandler struct {
	service *CRLService
}

// NewCRLHandler creates a new CRL handler
func NewCRLHandler(service *CRLService) *CRLHandler {
	return &CRLHandler{
		service: service,
	}
}

// ============================================================================
// Credential Management Handlers
// ============================================================================

// HandleRegisterCredentialID handles POST /credentials
func (h *CRLHandler) HandleRegisterCredentialID(w http.ResponseWriter, r *http.Request) {
	var req registerCredentialIDRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body", err)
		return
	}

	if req.SerialNumber == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "serialNumber is required", nil)
		return
	}

	resp, err := h.service.RegisterCredentialID(req.SerialNumber, req.CRLId)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "already_exists", "Certificate already registered", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to register credential", err)
		return
	}

	respondJSON(w, http.StatusCreated, resp)
}

// HandleListCredentials handles GET /credential-ids
func (h *CRLHandler) HandleListCredentials(w http.ResponseWriter, _ *http.Request) {
	credentials, err := h.service.ListCredentials()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to list credentials", err)
		return
	}

	respondJSON(w, http.StatusOK, credentials)
}

// ListCredentialInfoResponse is the response of the GET /credential-ids
// endpoint
type ListCredentialInfoResponse []ListCredentialsResponseElement

// HandleGetCredential handles GET /credential-ids/{serialNumber}
func (h *CRLHandler) HandleGetCredential(w http.ResponseWriter, r *http.Request) {
	serialNumber := chi.URLParam(r, "serialNumber")
	if serialNumber == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "serialNumber is required", nil)
		return
	}

	cert, err := h.service.GetCredential(serialNumber)
	if err != nil {
		if err == ErrCertificateNotFound {
			writeError(w, http.StatusNotFound, "not_found", "Certificate not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get credential", err)
		return
	}

	respondJSON(w, http.StatusOK, cert)
}

// ============================================================================
// CRL Management Handlers
// ============================================================================

// HandleListCRLs handles GET /crl
func (h *CRLHandler) HandleListCRLs(w http.ResponseWriter, _ *http.Request) {
	crls := h.service.ListCRL()

	respondJSON(w, http.StatusOK, crls)
}

// HandleGetCRL handles GET /crl/{crlId}
func (h *CRLHandler) HandleGetCRL(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	crlDER, err := h.service.GetCRL(crlID)
	if err != nil {
		if err == ErrCRLNotFound {
			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get CRL", err)
		return
	}

	// Set appropriate headers for CRL
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crl"`, crlID))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(crlDER); err != nil {
		// TODO: add proper logging
		fmt.Println(err)
		return
	}
}

// HandleGetCRLForDomain handles GET /crl/{crlId}/domains/{domain}
func (h *CRLHandler) HandleGetCRLForDomain(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "domain is required", nil)
		return
	}

	// TODO: validate the domain

	crlDER, err := h.service.GetDBCRL(crlID, domain)
	if err != nil {
		if err == ErrCRLNotFound {
			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get CRL", err)
		return
	}

	// Set appropriate headers for CRL
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crl"`, crlID))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(crlDER); err != nil {
		// TODO: add proper logging
		fmt.Println(err)
		return
	}
}

// HandleGetCRLInfo handles GET /crl/{crlId}/info
func (h *CRLHandler) HandleGetCRLInfo(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	info, err := h.service.GetCRLInfo(crlID)
	if err != nil {
		if err == ErrCRLNotFound {
			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get CRL info", err)
		return
	}

	respondJSON(w, http.StatusOK, info)
}

// HandleListCRLSerialNumbers handles GET /crl/{crlId}/serial-numbers
// func (h *CRLHandler) HandleListCRLSerialNumbers(w http.ResponseWriter, r *http.Request) {
// 	crlID := chi.URLParam(r, "crlId")
// 	if crlID == "" {
// 		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
// 		return
// 	}
//
// 	serials, err := h.service.ListCRLSerialNumbers(crlID)
// 	if err != nil {
// 		if err == ErrCRLNotFound {
// 			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
// 			return
// 		}
// 		writeError(w, http.StatusInternalServerError, "internal", "Failed to list serial numbers", err)
// 		return
// 	}
//
// 	respondJSON(w, http.StatusOK, map[string]interface{}{
// 		"serialNumbers": serials,
// 	})
// }

// ============================================================================
// Revocation Handlers
// ============================================================================

// HandleRevoke handles POST /crl/{crlId}/revoke
func (h *CRLHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body", err)
		return
	}

	var req RevokeCertificatesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body", err)
		return
	}

	if len(req.SerialNumbers) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_argument", "At least one serial number is required", nil)
		return
	}

	resp, err := h.service.Revoke(crlID, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to revoke certificates", err)
		return
	}

	// Return 207 Multi-Status if there were any failures
	status := http.StatusOK
	if len(resp.Failed) > 0 && len(resp.Success) > 0 {
		status = http.StatusMultiStatus
	} else if len(resp.Failed) > 0 {
		status = http.StatusBadRequest
	}

	respondJSON(w, status, resp)
}

// ============================================================================
// Mini CRL Handlers
// ============================================================================

// HandleListMiniCRLs handles GET /crl/{crlId}/mini-crls
func (h *CRLHandler) HandleListMiniCRLs(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	// Check for serialNumber query parameter
	serialNumber := r.URL.Query().Get("serialNumber")

	// List all mini CRLs
	resp, err := h.service.ListMiniCRL(crlID)
	if err != nil {
		if err == ErrCRLNotFound {
			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to list mini CRLs", err)
		return
	}

	if serialNumber != "" {
		snBytes, err := base64.RawURLEncoding.DecodeString(serialNumber)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "Failed to decode the serial number", err)
			return
		}
		var sn *big.Int
		sn.FillBytes(snBytes)
		r := resp
		for _, v := range resp.MiniCRLs {
			if v.SerialNumberLow.Cmp(sn) == -1 && v.SerialNumberHigh.Cmp(sn) == 1 {
				r.MiniCRLs = []MiniCRLRange{v}
				respondJSON(w, http.StatusOK, r)
			}

		}
		writeError(w, http.StatusNotFound, "not_found", "CRL for the specified serial number not found", err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// HandleGetMiniCRLBySerialNumber handles GET /crl/{crlId}/mini-crls?serialNumber={sn}
func (h *CRLHandler) HandleGetMiniCRLBySerialNumber(w http.ResponseWriter, r *http.Request) {

	crlID := chi.URLParam(r, "crlId")
	if crlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId is required", nil)
		return
	}

	// Check for serialNumber query parameter
	serialNumber := r.URL.Query().Get("serialNumber")
	if serialNumber == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "serialID is required", nil)
		return
	}

	crlDER, err := h.service.GetMiniCRLBySerialNumber(crlID, serialNumber)
	if err != nil {
		if err == ErrCertificateNotFound {
			writeError(w, http.StatusNotFound, "not_found", "Certificate not found", err)
			return
		}
		if err == ErrSerialNotInRange {
			writeError(w, http.StatusNotFound, "not_found", "Serial number not in any mini CRL range", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get mini CRL", err)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-mini.crl"`, crlID))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(crlDER); err != nil {
		return
	}
}

// HandleGetMiniCRL handles GET /crl/{crlId}/mini-crls/{miniCrlId}
func (h *CRLHandler) HandleGetMiniCRL(w http.ResponseWriter, r *http.Request) {
	crlID := chi.URLParam(r, "crlId")
	miniCrlID := chi.URLParam(r, "miniCrlId")

	if crlID == "" || miniCrlID == "" {
		writeError(w, http.StatusBadRequest, "invalid_argument", "crlId and miniCrlId are required", nil)
		return
	}

	crlDER, err := h.service.GetMiniCRLByID(crlID, miniCrlID)
	if err != nil {
		if err == ErrCRLNotFound {
			writeError(w, http.StatusNotFound, "not_found", "CRL not found", err)
			return
		}
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "not_found", "Mini CRL not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get mini CRL", err)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.crl"`, miniCrlID))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(crlDER); err != nil {
		return
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// ErrorResponse represents a Google API-compliant error response
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains error information
type ErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
}

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// writeError writes a Google API-compliant error response
func writeError(w http.ResponseWriter, status int, errorStatus, message string, err error) {
	details := ""
	if err != nil {
		details = err.Error()
	}

	resp := ErrorResponse{
		Error: ErrorDetail{
			Code:    status,
			Message: message,
			Status:  errorStatus,
			Details: details,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}

// ============================================================================
// HTTP Discovery Handlers
// ============================================================================

// HandleDiscovery handles endpoint discovery information
func (h *CRLHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Build discovery response
	discovery := discovery.Response{
		Service: discovery.ServiceInfo{
			Name:        "CRL Services",
			Version:     "0.1.0",
			Description: "Revocation services to showcase Mini CRL and Domain-bound CRL capabilities",
		},
	}

	discovery.Links = GetCRLServiceLinks()
	discovery.Endpoints = GetEndpointDefinitions()

	respondJSON(w, http.StatusOK, discovery)

}
