package api

import (
	"reflect"
	"strings"
	"time"
)

// CreateSchemaInfo creates API endpoint definitions
func CreateSchemaInfo(contentType string, structType any, example any) *SchemaInfo {
	return &SchemaInfo{
		ContentType: contentType,
		Schema:      GenerateSchema(structType),
		Example:     example,
	}
}

// SchemaInfo contains API definition information
type SchemaInfo struct {
	ContentType string         `json:"contentType"`
	Schema      map[string]any `json:"schema"`
	Example     any            `json:"example,omitempty"`
}

// GenerateSchema creates a JSON schema from a Go struct using reflection
func GenerateSchema(v any) map[string]any {
	t := reflect.TypeOf(v)

	// Handle pointer types
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return map[string]any{
			"type": strings.ToLower(t.Kind().String()),
		}
	}

	properties := make(map[string]any)
	required := []string{}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get JSON tag
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		// Parse JSON tag
		jsonName := field.Name
		isRequired := true
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			jsonName = parts[0]
			for _, option := range parts[1:] {
				if option == "omitempty" {
					isRequired = false
				}
			}
		}

		// Get description from comment tag if available
		description := field.Tag.Get("description")
		example := field.Tag.Get("example")

		// Build field schema
		fieldSchema := map[string]any{
			"type": getJSONType(field.Type),
		}

		if description != "" {
			fieldSchema["description"] = description
		}

		if example != "" {
			fieldSchema["example"] = example
		}

		// Handle nested structs
		if field.Type.Kind() == reflect.Struct && field.Type != reflect.TypeOf(time.Time{}) {
			fieldSchema = GenerateSchema(reflect.New(field.Type).Elem().Interface())
		}

		// Handle slices/arrays
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array {
			elemType := field.Type.Elem()
			fieldSchema["type"] = "array"
			if elemType.Kind() == reflect.Struct {
				fieldSchema["items"] = GenerateSchema(reflect.New(elemType).Elem().Interface())
			} else {
				fieldSchema["items"] = map[string]any{
					"type": getJSONType(elemType),
				}
			}
		}

		// Handle maps
		if field.Type.Kind() == reflect.Map {
			fieldSchema["type"] = "object"
			fieldSchema["additionalProperties"] = true
		}

		properties[jsonName] = fieldSchema

		if isRequired {
			required = append(required, jsonName)
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}

// getJSONType converts Go type to JSON schema type
func getJSONType(t reflect.Type) string {
	// Handle pointer types
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	default:
		return "string"
	}
}
