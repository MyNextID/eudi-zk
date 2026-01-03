package api

import (
	"net/http"
	"time"
)

// GetHealthResponse returns server's healt status information
type GetHealthResponse struct {
	Status string `json:"status" description:"Server health status information."`
	Time   string `json:"time" description:"Time of the response (UTC)"`
}

// HandleHealth handles health check requests
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	respondJSON(w, http.StatusOK, GetHealthResponse{
		Status: "healthy",
		Time:   time.Now().UTC().Format(time.RFC3339),
	})
}

// Experimental

// Definition holds information about the API
type Definition struct {
	Name    string `json:"name"`
	Version uint   `json:"version"`
	Handler http.HandlerFunc
	Info    *EndpointInfo `json:"info"`
}

// Endpoint info
var HealthDefinition = Definition{
	Name:    "health",
	Version: 1,
	// Handler: Health{}.GetHealth,
	Info: &EndpointInfo{
		Description: "Health check endpoint for monitoring",
		Path:        "/health",
		Methods:     []string{"GET"},
		Response:    CreateSchemaInfo("application/json", GetHealthResponse{}, nil),
	},
}
