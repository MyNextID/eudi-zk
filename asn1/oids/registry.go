package oids

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"strings"
)

// OIDInfo represents information about an Object Identifier.
type OIDInfo struct {
	OID         string
	Description string
	Comment     string
	Warning     bool // true if this OID should trigger a warning
}

// Registry holds a collection of parsed OID information.
type Registry struct {
	entries map[string]*OIDInfo
}

// NewRegistry creates a new empty OID registry.
func NewRegistry() *Registry {
	return &Registry{
		entries: make(map[string]*OIDInfo),
	}
}

// Parse reads a dumpasn1.cfg file and populates the registry.
func (r *Registry) Parse(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	var current *OIDInfo
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip blank lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Parse attribute line
		parts := strings.SplitN(line, "=", 2)

		// Check if this is a Warning flag (no '=' sign)
		if len(parts) == 1 {
			attr := strings.TrimSpace(parts[0])
			if attr == "Warning" {
				if current == nil {
					return fmt.Errorf("line %d: Warning without preceding OID", lineNum)
				}
				current.Warning = true
				continue
			}
			return fmt.Errorf("line %d: invalid format, expected 'attribute = value' or 'Warning'", lineNum)
		}

		attr := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch attr {
		case "OID":
			// OID attribute starts a new entry
			if current != nil {
				// Validate and save the previous entry
				if err := r.addEntry(current); err != nil {
					return fmt.Errorf("line %d: %w", lineNum, err)
				}
			}
			current = &OIDInfo{OID: value}

		case "Description":
			if current == nil {
				return fmt.Errorf("line %d: Description without preceding OID", lineNum)
			}
			current.Description = value

		case "Comment":
			if current == nil {
				return fmt.Errorf("line %d: Comment without preceding OID", lineNum)
			}
			current.Comment = value

		default:
			return fmt.Errorf("line %d: unknown attribute '%s'", lineNum, attr)
		}
	}

	// Don't forget the last entry
	if current != nil {
		if err := r.addEntry(current); err != nil {
			return fmt.Errorf("end of file: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning error: %w", err)
	}

	return nil
}

// addEntry validates and adds an OID entry to the registry.
func (r *Registry) addEntry(info *OIDInfo) error {
	if info.OID == "" {
		return fmt.Errorf("OID cannot be empty")
	}
	if info.Description == "" {
		return fmt.Errorf("Description is required for OID %s", info.OID)
	}

	r.entries[info.OID] = info
	return nil
}

// Lookup retrieves OID information by OID string.
func (r *Registry) Lookup(oid string) (*OIDInfo, bool) {
	info, found := r.entries[DotToSpace(oid)]
	return info, found
}

// LookupDescription returns just the description for an OID, or empty string if not found.
func (r *Registry) LookupDescription(oid string) string {
	if info, found := r.entries[DotToSpace(oid)]; found {
		return info.Description
	}
	return ""
}

// Count returns the number of OIDs in the registry.
func (r *Registry) Count() int {
	return len(r.entries)
}

// All returns all OID entries in the registry.
func (r *Registry) All() map[string]*OIDInfo {
	// Return a copy to prevent external modification
	result := make(map[string]*OIDInfo, len(r.entries))
	maps.Copy(result, r.entries)
	return result
}

// ParseFile is a convenience function that creates a registry and parses in one step.
func ParseFile(reader io.Reader) (*Registry, error) {
	registry := NewRegistry()
	if err := registry.Parse(reader); err != nil {
		return nil, err
	}
	return registry, nil
}

// DotToSpace replaces all dots with spaces
func DotToSpace(in string) string {
	return strings.ReplaceAll(in, ".", " ")
}
