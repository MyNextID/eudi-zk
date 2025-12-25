package api

/* openAPI specs - draft outline

// Field represents a single input field
type Field struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "bytes", "hash", "signature"
	Size        int    `json:"size"` // Expected array length
	Description string `json:"description"`
	IsPublic    bool   `json:"is_public"` // Public or private input
}

// CircuitList - Simple configuration that generates OpenAPI automatically
var CircuitListOpenAPI = map[string]CircuitInfo{
	"compare-bytes-b64url": {
		Circuit: &ccb.CircuitB64Url{
			Bytes:    make([]uints.U8, BYTE_SIZE64),
			BytesB64: make([]uints.U8, BYTE_SIZE64_B64),
		},
		Name:        "compare-bytes-b64url",
		Version:     1,
		Description: "Proves that base64url encoded bytes decode to the claimed bytes",
		Fields: []Field{
			{
				Name:        "bytes_b64",
				Type:        "bytes",
				Size:        BYTE_SIZE64_B64,
				Description: "Base64url encoded bytes",
				IsPublic:    true,
			},
			{
				Name:        "bytes",
				Type:        "bytes",
				Size:        BYTE_SIZE64,
				Description: "Original bytes (secret)",
				IsPublic:    false,
			},
		},
	},
	"compare-bytes": {
		Circuit: &ccb.CircuitBytes{
			Bytes:    make([]uints.U8, BYTE_SIZE64),
			PubBytes: make([]uints.U8, BYTE_SIZE64),
		},
		Name:        "compare-bytes",
		Version:     1,
		Description: "Proves that two byte arrays are equal",
		Fields: []Field{
			{
				Name:        "pub_bytes",
				Type:        "bytes",
				Size:        BYTE_SIZE64,
				Description: "Expected bytes to compare against",
				IsPublic:    true,
			},
			{
				Name:        "bytes",
				Type:        "bytes",
				Size:        BYTE_SIZE64,
				Description: "Bytes to verify (secret)",
				IsPublic:    false,
			},
		},
	},
	"compare-bytes-cnf": {
		Circuit: &ccb.CircuitCompareCnf{
			HeaderB64:       make([]uints.U8, BYTE_SIZE128),
			CnfB64:          make([]uints.U8, BYTE_SIZE1024),
			PublicKeyDigest: make([]uints.U8, BYTE_SIZE32),
		},
		Name:        "compare-bytes-cnf",
		Version:     1,
		Description: "Proves CNF data matches header and public key digest",
		Fields: []Field{
			{
				Name:        "public_key_digest",
				Type:        "hash",
				Size:        BYTE_SIZE32,
				Description: "SHA-256 digest of public key",
				IsPublic:    true,
			},
			{
				Name:        "header_b64",
				Type:        "bytes",
				Size:        BYTE_SIZE128,
				Description: "Base64 encoded header (secret)",
				IsPublic:    false,
			},
			{
				Name:        "cnf_b64",
				Type:        "bytes",
				Size:        BYTE_SIZE1024,
				Description: "Base64 encoded CNF data (secret)",
				IsPublic:    false,
			},
		},
	},
}

// GetPublicFields returns all public input fields
func (c CircuitInfo) GetPublicFields() []Field {
	var fields []Field
	for _, f := range c.Fields {
		if f.IsPublic {
			fields = append(fields, f)
		}
	}
	return fields
}

// GetPrivateFields returns all private input fields
func (c CircuitInfo) GetPrivateFields() []Field {
	var fields []Field
	for _, f := range c.Fields {
		if !f.IsPublic {
			fields = append(fields, f)
		}
	}
	return fields
}

// GenerateOpenAPISpec generates a complete OpenAPI 3.0 spec from CircuitList
func GenerateOpenAPISpec(title, version, baseURL string) ([]byte, error) {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       title,
			Description: "Zero-Knowledge Proof API for circuit verification",
			Version:     version,
		},
		Servers: []OpenAPIServer{
			{URL: baseURL, Description: "Production server"},
		},
		Paths: make(map[string]PathItem),
		Components: OpenAPIComponents{
			Schemas: make(map[string]interface{}),
		},
	}

	// Add health endpoint
	spec.Paths["/health"] = PathItem{
		Get: &Operation{
			Summary:     "Health check",
			Description: "Check if the service is running",
			OperationID: "health",
			Tags:        []string{"system"},
			Responses: map[string]Response{
				"200": {
					Description: "Service is healthy",
					Content: map[string]MediaType{
						"application/json": {
							Schema: &Schema{
								Type: "object",
								Properties: map[string]interface{}{
									"status": map[string]string{"type": "string"},
									"time":   map[string]string{"type": "string"},
								},
							},
						},
					},
				},
			},
		},
	}

	// Add circuits list endpoint
	spec.Paths["/circuits"] = PathItem{
		Get: &Operation{
			Summary:     "List all circuits",
			Description: "Get a list of all available circuits",
			OperationID: "listCircuits",
			Tags:        []string{"circuits"},
			Responses: map[string]Response{
				"200": {
					Description: "List of circuits",
					Content: map[string]MediaType{
						"application/json": {
							Schema: &Schema{Ref: "#/components/schemas/CircuitListResponse"},
						},
					},
				},
			},
		},
	}

	// Generate endpoints for each circuit
	for name, info := range CircuitList {
		// Add circuit info endpoint
		spec.Paths["/circuits/{circuit}"] = PathItem{
			Get: &Operation{
				Summary:     "Get circuit information",
				Description: "Get detailed information about a specific circuit",
				OperationID: "getCircuit",
				Tags:        []string{"circuits"},
				Parameters: []Parameter{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Circuit name",
						Required:    true,
						Schema:      &Schema{Type: "string", Enum: getCircuitNames()},
					},
				},
				Responses: map[string]Response{
					"200": {
						Description: "Circuit information",
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{Ref: "#/components/schemas/CircuitInfoResponse"},
							},
						},
					},
					"404": {Description: "Circuit not found"},
				},
			},
		}

		// Generate schemas for this circuit
		publicSchemaName := fmt.Sprintf("%sPublicInput", toCamelCase(name))
		privateSchemaName := fmt.Sprintf("%sPrivateInput", toCamelCase(name))

		spec.Components.Schemas[publicSchemaName] = generateSchemaFromFields(info.GetPublicFields())
		spec.Components.Schemas[privateSchemaName] = generateSchemaFromFields(info.GetPrivateFields())

		// Add prove endpoint
		proveRequestSchema := map[string]interface{}{
			"type":     "object",
			"required": []string{"public_input", "private_input"},
			"properties": map[string]interface{}{
				"public_input": map[string]interface{}{
					"$ref": fmt.Sprintf("#/components/schemas/%s", publicSchemaName),
				},
				"private_input": map[string]interface{}{
					"$ref": fmt.Sprintf("#/components/schemas/%s", privateSchemaName),
				},
			},
		}

		spec.Paths["/prove/{circuit}"] = PathItem{
			Post: &Operation{
				Summary:     "Generate proof",
				Description: fmt.Sprintf("Generate a zero-knowledge proof for %s", info.Description),
				OperationID: fmt.Sprintf("prove%s", toCamelCase(name)),
				Tags:        []string{"proofs", name},
				Parameters: []Parameter{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Circuit name",
						Required:    true,
						Schema:      &Schema{Type: "string", Enum: getCircuitNames()},
					},
				},
				RequestBody: &RequestBody{
					Description: "Public and private inputs for proof generation",
					Required:    true,
					Content: map[string]MediaType{
						"application/json": {
							Schema: &Schema{Properties: proveRequestSchema},
						},
					},
				},
				Responses: map[string]Response{
					"200": {
						Description: "Proof generated successfully",
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{Ref: "#/components/schemas/ProveResponse"},
							},
						},
					},
					"400": {Description: "Invalid input"},
					"404": {Description: "Circuit not found"},
					"500": {Description: "Proof generation failed"},
				},
			},
		}

		// Add verify endpoint
		verifyRequestSchema := map[string]interface{}{
			"type":     "object",
			"required": []string{"public_input", "proof"},
			"properties": map[string]interface{}{
				"public_input": map[string]interface{}{
					"$ref": fmt.Sprintf("#/components/schemas/%s", publicSchemaName),
				},
				"proof": map[string]interface{}{
					"type":        "string",
					"description": "Base64 encoded proof",
				},
			},
		}

		spec.Paths["/verify/{circuit}"] = PathItem{
			Post: &Operation{
				Summary:     "Verify proof",
				Description: fmt.Sprintf("Verify a zero-knowledge proof for %s", info.Description),
				OperationID: fmt.Sprintf("verify%s", toCamelCase(name)),
				Tags:        []string{"proofs", name},
				Parameters: []Parameter{
					{
						Name:        "circuit",
						In:          "path",
						Description: "Circuit name",
						Required:    true,
						Schema:      &Schema{Type: "string", Enum: getCircuitNames()},
					},
				},
				RequestBody: &RequestBody{
					Description: "Public input and proof for verification",
					Required:    true,
					Content: map[string]MediaType{
						"application/json": {
							Schema: &Schema{Properties: verifyRequestSchema},
						},
					},
				},
				Responses: map[string]Response{
					"200": {
						Description: "Verification result",
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{Ref: "#/components/schemas/VerifyResponse"},
							},
						},
					},
					"400": {Description: "Invalid input"},
					"404": {Description: "Circuit not found"},
				},
			},
		}
	}

	// Add common response schemas
	addCommonSchemas(spec)

	return json.MarshalIndent(spec, "", "  ")
}

// generateSchemaFromFields converts Field slice to JSON schema
func generateSchemaFromFields(fields []Field) map[string]interface{} {
	properties := make(map[string]interface{})
	required := []string{}

	for _, field := range fields {
		properties[field.Name] = map[string]interface{}{
			"type":        "array",
			"description": field.Description,
			"items": map[string]interface{}{
				"type":    "integer",
				"minimum": 0,
				"maximum": 255,
			},
			"minItems": field.Size,
			"maxItems": field.Size,
		}
		required = append(required, field.Name)
	}

	return map[string]interface{}{
		"type":       "object",
		"properties": properties,
		"required":   required,
	}
}

// addCommonSchemas adds reusable schemas
func addCommonSchemas(spec *OpenAPISpec) {
	spec.Components.Schemas["ProveResponse"] = map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"proof":     map[string]string{"type": "string", "description": "Base64 encoded proof"},
			"circuit":   map[string]string{"type": "string"},
			"timestamp": map[string]string{"type": "string", "format": "date-time"},
		},
	}

	spec.Components.Schemas["VerifyResponse"] = map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"valid":     map[string]string{"type": "boolean"},
			"circuit":   map[string]string{"type": "string"},
			"timestamp": map[string]string{"type": "string", "format": "date-time"},
			"message":   map[string]string{"type": "string"},
		},
	}

	spec.Components.Schemas["CircuitInfoResponse"] = map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"name":    map[string]string{"type": "string"},
			"version": map[string]string{"type": "integer"},
			"loaded":  map[string]string{"type": "boolean"},
		},
	}

	spec.Components.Schemas["CircuitListResponse"] = map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"circuits": map[string]interface{}{
				"type": "array",
				"items": map[string]string{
					"$ref": "#/components/schemas/CircuitInfoResponse",
				},
			},
			"count": map[string]string{"type": "integer"},
		},
	}
}

// Helper functions
func getCircuitNames() []string {
	names := make([]string, 0, len(CircuitList))
	for name := range CircuitList {
		names = append(names, name)
	}
	return names
}

func toCamelCase(s string) string {
	// Simple conversion: remove hyphens and capitalize
	result := ""
	capitalize := true
	for _, c := range s {
		if c == '-' {
			capitalize = true
			continue
		}
		if capitalize {
			result += string(c - 32) // Simple uppercase
			capitalize = false
		} else {
			result += string(c)
		}
	}
	return result
}

// ============================================================================
// OpenAPI Types
// ============================================================================

type OpenAPISpec struct {
	OpenAPI    string              `json:"openapi"`
	Info       OpenAPIInfo         `json:"info"`
	Servers    []OpenAPIServer     `json:"servers"`
	Paths      map[string]PathItem `json:"paths"`
	Components OpenAPIComponents   `json:"components"`
}

type OpenAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

type PathItem struct {
	Get  *Operation `json:"get,omitempty"`
	Post *Operation `json:"post,omitempty"`
}

type Operation struct {
	Summary     string              `json:"summary"`
	Description string              `json:"description,omitempty"`
	OperationID string              `json:"operationId"`
	Tags        []string            `json:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
}

type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Description string  `json:"description,omitempty"`
	Required    bool    `json:"required"`
	Schema      *Schema `json:"schema"`
}

type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required"`
	Content     map[string]MediaType `json:"content"`
}

type MediaType struct {
	Schema *Schema `json:"schema"`
}

type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

type Schema struct {
	Type       string                 `json:"type,omitempty"`
	Ref        string                 `json:"$ref,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
	Items      map[string]interface{} `json:"items,omitempty"`
	Enum       []string               `json:"enum,omitempty"`
}

type OpenAPIComponents struct {
	Schemas map[string]interface{} `json:"schemas"`
}
*/
