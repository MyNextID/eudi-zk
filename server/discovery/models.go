// Package discovery defines the discovery endpoint data models and functions
package discovery

// ============================================================================
// Endpoint Definitions for Discovery
// ============================================================================

// EndpointInfo represents information about an API endpoint
// This mirrors the api.EndpointInfo structure from your existing code
type EndpointInfo struct {
	Description     string          `json:"description"`
	LongDescription string          `json:"longDescription,omitempty"`
	Path            string          `json:"path"`
	Method          string          `json:"methods"`
	Parameters      []ParameterInfo `json:"parameters,omitempty"`
	Request         *SchemaInfo     `json:"request,omitempty"`
	Response        *SchemaInfo     `json:"response,omitempty"`
	Examples        map[string]any  `json:"examples,omitempty"`
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

// SchemaInfo represents request/response schema information
type SchemaInfo struct {
	ContentType string         `json:"contentType"`
	Schema      map[string]any `json:"schema"`
	Example     any            `json:"example,omitempty"`
}

// PropertyInfo represents a schema property
type PropertyInfo struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Example     any    `json:"example,omitempty"`
	Format      string `json:"format,omitempty"`
}

// ServiceInfo represents service metadata
type ServiceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Repository  string `json:"repository,omitempty"`
	License     string `json:"license,omitempty"`
	Commit      string `json:"commit,omitempty"`
	Description string `json:"description"`
	Environment string `json:"environment,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
	GoVersion   string `json:"go_version,omitempty"`
}

// Response represents the API discovery information
type Response struct {
	Service   ServiceInfo             `json:"service"`
	Endpoints map[string]EndpointInfo `json:"endpoints"`
	Links     map[string]string       `json:"links,omitempty"`
}
