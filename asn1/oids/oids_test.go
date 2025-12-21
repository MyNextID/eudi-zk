package oids_test

import (
	"os"
	"strings"
	"testing"

	"github.com/mynextid/asn1/oids"
)

func TestParseBasic(t *testing.T) {
	input := `# Comment line
OID = 1.2.840.113549.1.1.1
Description = RSA encryption
Comment = PKCS #1

OID = 1.2.840.113549.1.1.5
Description = SHA-1 with RSA signature
Warning

# Another comment
OID = 2.5.4.3
Description = Common Name
`

	registry, err := oids.ParseFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if registry.Count() != 3 {
		t.Errorf("Expected 3 entries, got %d", registry.Count())
	}

	// Test lookup
	info, found := registry.Lookup("1.2.840.113549.1.1.1")
	if !found {
		t.Fatal("RSA OID not found")
	}
	if info.Description != "RSA encryption" {
		t.Errorf("Wrong description: %s", info.Description)
	}
	if info.Comment != "PKCS #1" {
		t.Errorf("Wrong comment: %s", info.Comment)
	}

	// Test warning
	info, found = registry.Lookup("1.2.840.113549.1.1.5")
	if !found || !info.Warning {
		t.Error("Warning not parsed correctly")
	}

	// Test description lookup
	desc := registry.LookupDescription("2.5.4.3")
	if desc != "Common Name" {
		t.Errorf("Wrong description: %s", desc)
	}
}

func TestParseRealFile(t *testing.T) {
	// Download the real file first:
	// wget https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg

	f, err := os.Open("dumpasn1.cfg")
	if err != nil {
		t.Skip("dumpasn1.cfg not found, skipping real file test")
		return
	}
	defer f.Close()

	registry, err := oids.ParseFile(f)
	if err != nil {
		t.Fatalf("Failed to parse real file: %v", err)
	}

	t.Logf("Parsed %d OIDs from dumpasn1.cfg", registry.Count())

	// Verify some common OIDs
	commonOIDs := []struct {
		oid  string
		desc string
	}{
		{"2.5.4.3", "CommonName"},
		{"2.5.4.6", "Country"},
		{"2.5.4.10", "Organization"},
	}

	for _, tc := range commonOIDs {
		desc := registry.LookupDescription(tc.oid)
		if !strings.Contains(strings.ToLower(desc), strings.ToLower(tc.desc)) {
			t.Errorf("OID %s: expected description containing %q, got %q",
				tc.oid, tc.desc, desc)
		}
	}
}

func TestErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"missing description", "OID = 1.2.3\n"},
		{"description before OID", "Description = test\n"},
		{"invalid format", "InvalidLine\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := oids.ParseFile(strings.NewReader(tt.input))
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}
