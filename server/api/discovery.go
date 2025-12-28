// Package api implements the REST endpoints
package api

import (
	"net/http"
	"runtime"
	"time"
)

// DiscoveryResponse represents the API discovery information
type DiscoveryResponse struct {
	Service   ServiceInfo             `json:"service"`
	Endpoints map[string]EndpointInfo `json:"endpoints"`
	Circuits  CircuitsSummary         `json:"circuits"`
	Links     map[string]string       `json:"links,omitempty"`
}

// ServiceInfo represents service metadata
type ServiceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	Description string `json:"description"`
	Environment string `json:"environment,omitempty"`
	Uptime      string `json:"uptime"`
	GoVersion   string `json:"go_version"`
}

// EndpointInfo represents information about an API endpoint
type EndpointInfo struct {
	Description string          `json:"description"`
	Path        string          `json:"path"`
	Methods     []string        `json:"methods"`
	Parameters  []ParameterInfo `json:"parameters,omitempty"`
	Request     *RequestInfo    `json:"request,omitempty"`
	Response    *ResponseInfo   `json:"response,omitempty"`
	Examples    map[string]any  `json:"examples,omitempty"`
}

// ParameterInfo represents URL or query parameters
type ParameterInfo struct {
	Name        string `json:"name"`
	In          string `json:"in"` // "path", "query", "header"
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`
	Example     string `json:"example,omitempty"`
}

// RequestInfo represents request body information
type RequestInfo struct {
	ContentType string         `json:"content_type"`
	Schema      map[string]any `json:"schema,omitempty"`
	Example     any            `json:"example,omitempty"`
}

// ResponseInfo represents response information
type ResponseInfo struct {
	ContentType string         `json:"content_type"`
	Schema      map[string]any `json:"schema,omitempty"`
	Example     any            `json:"example,omitempty"`
}

// CircuitsSummary provides a summary of available circuits
type CircuitsSummary struct {
	Total     int      `json:"total"`
	Loaded    int      `json:"loaded"`
	Available []string `json:"available"`
}

var serverStartTime = time.Now()

// HandleDiscovery handles endpoint discovery information
func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Calculate circuits summary
	totalCircuits := len(CircuitList)
	loadedCircuits := len(s.registry.circuits)
	availableNames := make([]string, 0, totalCircuits)
	for name := range CircuitList {
		availableNames = append(availableNames, name)
	}

	// Build discovery response
	discovery := DiscoveryResponse{
		Service: ServiceInfo{
			Name:        "ZKPI",
			Description: "Zero-knowledge proof generation and verification service for digital identity frameworks",
			Version:     Version,
			Commit:      Commit,
			Uptime:      time.Since(serverStartTime).Round(time.Second).String(),
			GoVersion:   runtime.Version(),
		},
		Links: map[string]string{
			"repository": "https://github.com/mynextid/eudi-zk",
			"discovery":  "/",
			"circuits":   "/circuits",
			"health":     "/health",
		},
		Endpoints: map[string]EndpointInfo{
			"discovery": {
				Description: "API discovery and documentation endpoint",
				Path:        "/",
				Methods:     []string{"GET"},
				Response: &ResponseInfo{
					ContentType: "application/json",
				},
			},
			"health": {
				Description: "Health check endpoint for monitoring",
				Path:        "/health",
				Methods:     []string{"GET"},
				Response: &ResponseInfo{
					ContentType: "application/json",
					Example: map[string]string{
						"status": "healthy",
						"time":   time.Now().Format(time.RFC3339),
					},
				},
			},
			"list_circuits": {
				Description: "List all available zero-knowledge circuits",
				Path:        "/circuits",
				Methods:     []string{"GET"},
				Response: &ResponseInfo{
					ContentType: "application/json",
				},
			},
			"get_circuit": {
				Description: "Get information about a specific circuit",
				Path:        "/circuits/{circuit}",
				Methods:     []string{"GET"},
				Parameters: []ParameterInfo{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Name of the circuit",
						Required:    true,
						Type:        "string",
						Example:     "compare-bytes",
					},
				},
				Response: &ResponseInfo{
					ContentType: "application/json",
					Example: map[string]any{
						"name":    "compare-bytes",
						"version": 1,
						"loaded":  true,
					},
				},
			},
			"prove": {
				Description: "Generate a zero-knowledge proof using a circuit",
				Path:        "/prove/{circuit}",
				Methods:     []string{"POST"},
				Parameters: []ParameterInfo{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Name of the circuit to use for proof generation",
						Required:    true,
						Type:        "string",
						Example:     "compare-bytes",
					},
				},
			},
			"verify": {
				Description: "Verify a zero-knowledge proof",
				Path:        "/verify/{circuit}",
				Methods:     []string{"POST"},
				Parameters: []ParameterInfo{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Name of the circuit used for proof generation",
						Required:    true,
						Type:        "string",
						Example:     "compare-bytes",
					},
				},
			},
		},
		Circuits: CircuitsSummary{
			Total:     totalCircuits,
			Loaded:    loadedCircuits,
			Available: availableNames,
		},
	}

	respondJSON(w, http.StatusOK, discovery)
}
