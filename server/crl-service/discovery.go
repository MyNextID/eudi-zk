package crlservice

import "github.com/mynextid/eudi-zk/server/discovery"

// ============================================================================
// Endpoint Definition Objects
// ============================================================================

// RegisterCredentialIDDefinition defines the register credential endpoint
var RegisterCredentialIDDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "Register a new credential id and link it to a CRL",
		LongDescription: "Creates a new certificate id entry and associates it with a Certificate Revocation List (CRL). If no CRL ID is provided, a new CRL will be created automatically.",
		Path:            "/credential-ids",
		Method:          "POST",
		Request:         discovery.CreateSchemaInfo("application/json", registerCredentialIDRequest{}, nil),
		Response:        discovery.CreateSchemaInfo("application/json", RegisterCredentialIDResponse{}, nil),
	},
}

// ListCredentialsDefinition defines the list credentials endpoint
var ListCredentialsDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description: "List all registered credential ids",
		Path:        "/credential-ids",
		Method:      "GET",
		Response:    discovery.CreateSchemaInfo("application/json", ListCredentialInfoResponse{}, nil),
	},
}

// GetCredentialIDDefinition defines the get credential endpoint
var GetCredentialIDDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description: "Get a specific credential info by serial number",
		Path:        "/credential-ids/{serialNumber}",
		Method:      "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "serialNumber",
				In:          "path",
				Description: "Base64url-encoded certificate serial number",
				Required:    true,
				Type:        "string",
				Example:     "MTIzNDU2Nzg5MA",
			},
		},
		Response: discovery.CreateSchemaInfo("application/json", CertificateInfo{}, nil),
	},
}

// ListCRLsDefinition defines the list CRLs endpoint
var ListCRLsDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description: "List all registered CRL IDs",
		Path:        "/crl",
		Method:      "GET",
		Response:    discovery.CreateSchemaInfo("application/json", []ListCRLResponse{}, nil),
	},
}

// GetCRLDefinition defines the get CRL endpoint
var GetCRLDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "Download a Certificate Revocation List",
		LongDescription: "Returns a DER-encoded X.509 CRL in binary format.",
		Path:            "/crl/{crlId}",
		Method:          "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
		},
		Response: discovery.CreateSchemaInfo("application/pkix-crl", []byte{}, nil),
	},
}

// GetCRLForDomainDefinition defines the get DB-CRL endpoint
var GetCRLForDomainDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "Download a Domain Bound Certificate Revocation List",
		LongDescription: "Returns a DER-encoded X.509 CRL in binary format.",
		Path:            "/crl/{crlId}/domains/{domain}",
		Method:          "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
			{
				Name:        "domain",
				In:          "path",
				Description: "Domain identifier",
				Required:    true,
				Type:        "string",
				Example:     "example.com",
			},
		},
		Response: discovery.CreateSchemaInfo("application/pkix-crl", []byte{}, nil),
	},
}

// GetCRLInfoDefinition defines the get CRL info endpoint
var GetCRLInfoDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description: "Get metadata about a CRL",
		Path:        "/crl/{crlId}/info",
		Method:      "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
		},
		Response: discovery.CreateSchemaInfo("application/json", CRLInfo{}, nil),
	},
}

/*

// ListCRLSerialNumbersDefinition defines the list CRL serial numbers endpoint
var ListCRLSerialNumbersDefinition = struct {
	Info *EndpointInfo
}{
	Info: &EndpointInfo{
		Description: "List all serial numbers in a CRL",
		Path:        "/status/crl/{crlId}/serial-numbers",
		Methods:     []string{"GET"},
		Parameters: []ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
		},
		Response: &SchemaInfo{
			Type: "object",
			Properties: map[string]PropertyInfo{
				"serialNumbers": {
					Type:        "array",
					Description: "List of base64url-encoded serial numbers",
					Example:     []string{"MTIzNDU2Nzg5MA", "OTg3NjU0MzIxMA"},
				},
			},
		},
	},
}
*/

// RevokeCertificatesDefinition defines the revoke certificates endpoint
var RevokeCertificatesDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "Revoke one or more certificates",
		LongDescription: "Adds certificate serial numbers to the revocation list. Supports batch revocation with optional timestamp and reason codes following RFC 5280 standards.",
		Path:            "/crl/{crlId}/revoke",
		Method:          "POST",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
		},
		Request:  discovery.CreateSchemaInfo("application/json", RevokeCertificatesRequest{}, nil),
		Response: discovery.CreateSchemaInfo("application/json", RevokeCertificatesResponse{}, nil),
	},
}

// ListMiniCRLsDefinition defines the list mini CRLs endpoint
var ListMiniCRLsDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "List all mini CRL ranges for a CRL",
		LongDescription: "Returns partition information for mini CRLs. Mini CRLs divide the serial number space into ranges between registered certificates, enabling efficient selective downloads.",
		Path:            "/crl/{crlId}/mini-crls",
		Method:          "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
		},
		Response: discovery.CreateSchemaInfo("application/json", ListMiniCRLsResponse{}, nil),
	},
}

// GetMiniCRLDefinition defines the get mini CRL by ID endpoint
var GetMiniCRLDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description: "Download a specific mini CRL by its ID",
		Path:        "/crl/{crlId}/mini-crls/{miniCrlId}",
		Method:      "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
			{
				Name:        "miniCrlId",
				In:          "path",
				Description: "Mini CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "minicrl:abcd1234",
			},
		},
		Response: discovery.CreateSchemaInfo("application/pkix-crl", []byte{}, nil),
	},
}

// GetMiniCRLBySerialDefinition defines the get mini CRL by serial number endpoint
var GetMiniCRLBySerialDefinition = struct {
	Info *discovery.EndpointInfo
}{
	Info: &discovery.EndpointInfo{
		Description:     "Download the mini CRL containing a specific serial number",
		LongDescription: "Finds and returns the mini CRL that contains the specified serial number in its range. This allows efficient verification without downloading the entire CRL.",
		Path:            "/crl/{crlId}/mini-crls:lookup",
		Method:          "GET",
		Parameters: []discovery.ParameterInfo{
			{
				Name:        "crlId",
				In:          "path",
				Description: "CRL identifier",
				Required:    true,
				Type:        "string",
				Example:     "crl:a1b2c3d4e5f6g7h8i9j0",
			},
			{
				Name:        "serialNumber",
				In:          "query",
				Description: "Base64url-encoded serial number",
				Required:    true,
				Type:        "string",
				Example:     "MTIzNDU2Nzg5MA",
			},
		},
		Response: discovery.CreateSchemaInfo("application/pkix-crl", []byte{}, nil),
	},
}

// GetEndpointDefinitions returns all endpoint definitions for discovery integration
func GetEndpointDefinitions() map[string]discovery.EndpointInfo {
	return map[string]discovery.EndpointInfo{
		"register_credential": *RegisterCredentialIDDefinition.Info,
		"list_credentials":    *ListCredentialsDefinition.Info,
		"get_credential":      *GetCredentialIDDefinition.Info,
		"list_crls":           *ListCRLsDefinition.Info,
		"get_crl":             *GetCRLDefinition.Info,
		"get_crl_for_domain":  *GetCRLForDomainDefinition.Info,
		"get_crl_info":        *GetCRLInfoDefinition.Info,
		// "list_crl_serial_numbers": *ListCRLSerialNumbersDefinition.Info,
		"revoke_certificates":    *RevokeCertificatesDefinition.Info,
		"list_mini_crls":         *ListMiniCRLsDefinition.Info,
		"get_mini_crl":           *GetMiniCRLDefinition.Info,
		"get_mini_crl_by_serial": *GetMiniCRLBySerialDefinition.Info,
	}
}

// GetCRLServiceLinks returns the links for CRL service endpoints
func GetCRLServiceLinks() map[string]string {
	return map[string]string{
		"discovery":   "/discovery",
		"credentials": "/credentials",
		"crl":         "/crl",
		"dbCRL":       "/crl/{crlID}/domains",
		"revoke":      "/crl/{crlId}/revoke",
		"miniCRL":     "/crl/{crlId}/mini-crls",
	}
}
