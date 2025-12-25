package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Server handles HTTP requests for ZK proof operations
type Server struct {
	registry *CircuitRegistry
}

// NewServer creates a new HTTP server
func NewServer(registry *CircuitRegistry) *Server {
	return &Server{
		registry: registry,
	}
}

// ==== Request/Response Types ====

// ProveRequest represents a proof generation request
type ProveRequest struct {
	PublicInput  json.RawMessage `json:"public_input"`
	PrivateInput json.RawMessage `json:"private_input"`
}

// ProveResponse represents a proof generation response
type ProveResponse struct {
	Proof     string    `json:"proof"` // base64 encoded
	Timestamp time.Time `json:"timestamp"`
}

// VerifyRequest represents a proof verification request
type VerifyRequest struct {
	PublicInput json.RawMessage `json:"public_input"`
	Proof       string          `json:"proof"` // base64 encoded
}

// VerifyResponse represents a proof verification response
type VerifyResponse struct {
	Valid     bool      `json:"valid"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error     string    `json:"error"`
	Code      string    `json:"code,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// CircuitInfoResponse represents circuit information
type CircuitInfoResponse struct {
	Name    string `json:"name"`
	Version uint   `json:"version"`
	Loaded  bool   `json:"loaded"`
}

// CircuitListResponse represents a list of circuits
type CircuitListResponse struct {
	Circuits []CircuitInfoResponse `json:"circuits"`
	Count    int                   `json:"count"`
}

// ==== Handlers ====

// HandleHealth handles health check requests
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// HandleListCircuits lists all available circuits
func (s *Server) HandleListCircuits(w http.ResponseWriter, r *http.Request) {
	circuits := make([]CircuitInfoResponse, 0)

	for name, info := range CircuitList {
		_, loaded := s.registry.Circuits[name]
		circuits = append(circuits, CircuitInfoResponse{
			Name:    info.Name,
			Version: info.Version,
			Loaded:  loaded,
		})
	}

	respondJSON(w, http.StatusOK, CircuitListResponse{
		Circuits: circuits,
		Count:    len(circuits),
	})
}

// HandleGetCircuit gets information about a specific circuit
func (s *Server) HandleGetCircuit(w http.ResponseWriter, r *http.Request) {
	circuitName := chi.URLParam(r, "circuit")

	info, ok := CircuitList[circuitName]
	if !ok {
		respondError(w, http.StatusNotFound, "circuit_not_found",
			fmt.Sprintf("circuit '%s' not found", circuitName))
		return
	}

	_, loaded := s.registry.Circuits[circuitName]

	respondJSON(w, http.StatusOK, CircuitInfoResponse{
		Name:    info.Name,
		Version: info.Version,
		Loaded:  loaded,
	})
}

// HandleProve handles proof generation requests
func (s *Server) HandleProve(w http.ResponseWriter, r *http.Request) {
	circuitName := chi.URLParam(r, "circuit")

	// Check if circuit exists
	if _, ok := CircuitList[circuitName]; !ok {
		respondError(w, http.StatusNotFound, "circuit_not_found",
			fmt.Sprintf("circuit '%s' not found", circuitName))
		return
	}

	// Check if circuit is loaded
	circuit, err := s.registry.Get(circuitName)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "circuit_not_loaded",
			fmt.Sprintf("circuit '%s' is not loaded: %v", circuitName, err))
		return
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_request",
			"failed to read request body")
		return
	}
	defer r.Body.Close()

	var req ProveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json",
			fmt.Sprintf("failed to parse request: %v", err))
		return
	}

	// Validate inputs
	if len(req.PublicInput) == 0 || len(req.PrivateInput) == 0 {
		respondError(w, http.StatusBadRequest, "missing_input",
			"both public_input and private_input are required")
		return
	}

	// Generate proof
	proofBytes, err := circuit.ProveWithJSON(circuitName, req.PublicInput, req.PrivateInput)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "proof_generation_failed",
			fmt.Sprintf("failed to generate proof: %v", err))
		return
	}

	// Encode proof as base64
	proofB64 := base64.StdEncoding.EncodeToString(proofBytes)

	respondJSON(w, http.StatusOK, ProveResponse{
		Proof:     proofB64,
		Timestamp: time.Now(),
	})
}

// HandleVerify handles proof verification requests
func (s *Server) HandleVerify(w http.ResponseWriter, r *http.Request) {
	circuitName := chi.URLParam(r, "circuit")

	// Check if circuit exists
	if _, ok := CircuitList[circuitName]; !ok {
		respondError(w, http.StatusNotFound, "circuit_not_found",
			fmt.Sprintf("circuit '%s' not found", circuitName))
		return
	}

	// Check if circuit is loaded
	circuit, err := s.registry.Get(circuitName)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "circuit_not_loaded",
			fmt.Sprintf("circuit '%s' is not loaded: %v", circuitName, err))
		return
	}

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_request",
			"failed to read request body")
		return
	}
	defer r.Body.Close()

	var req VerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json",
			fmt.Sprintf("failed to parse request: %v", err))
		return
	}

	// Validate inputs
	if len(req.PublicInput) == 0 || req.Proof == "" {
		respondError(w, http.StatusBadRequest, "missing_input",
			"both public_input and proof are required")
		return
	}

	// Decode proof from base64
	proofBytes, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_proof_encoding",
			fmt.Sprintf("failed to decode proof: %v", err))
		return
	}

	// Verify proof
	err = circuit.Public().VerifyWithJSON(circuitName, req.PublicInput, proofBytes)

	response := VerifyResponse{
		Valid:     err == nil,
		Timestamp: time.Now(),
	}

	if err != nil {
		response.Message = fmt.Sprintf("verification failed: %v", err)
	} else {
		response.Message = "proof is valid"
	}

	respondJSON(w, http.StatusOK, response)
}

// ==== Helper Functions ====

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// respondError writes an error response
func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, ErrorResponse{
		Error:     message,
		Code:      code,
		Timestamp: time.Now(),
	})
}
