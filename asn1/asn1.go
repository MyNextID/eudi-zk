package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/mynextid/asn1/oids"
)

func parseASN1Value(data []byte) ([]asn1.RawValue, error) {
	var values []asn1.RawValue
	for len(data) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(data, &v)
		if err != nil {
			return values, err
		}
		values = append(values, v)
		data = rest
	}
	return values, nil
}

func getTagName(tag int, class int) string {
	// Context-specific, application, or private tags
	switch class {
	case 2: // Context-specific
		return fmt.Sprintf("[%d]", tag)
	case 1: // Application
		return fmt.Sprintf("[APPLICATION %d]", tag)
	case 3: // Private
		return fmt.Sprintf("[PRIVATE %d]", tag)
	}

	// Universal tags
	switch tag {
	case asn1.TagBoolean:
		return "BOOLEAN"
	case asn1.TagInteger:
		return "INTEGER"
	case asn1.TagBitString:
		return "BIT STRING"
	case asn1.TagOctetString:
		return "OCTET STRING"
	case asn1.TagNull:
		return "NULL"
	case asn1.TagOID:
		return "OBJECT IDENTIFIER"
	case asn1.TagEnum:
		return "ENUMERATED"
	case asn1.TagUTF8String:
		return "UTF8String"
	case asn1.TagSequence:
		return "SEQUENCE"
	case asn1.TagSet:
		return "SET"
	case asn1.TagNumericString:
		return "NumericString"
	case asn1.TagPrintableString:
		return "PrintableString"
	case asn1.TagT61String:
		return "T61String"
	case asn1.TagIA5String:
		return "IA5String"
	case asn1.TagUTCTime:
		return "UTCTime"
	case asn1.TagGeneralizedTime:
		return "GeneralizedTime"
	case asn1.TagGeneralString:
		return "GeneralString"
	default:
		return fmt.Sprintf("[UNIVERSAL %d]", tag)
	}
}

func formatContent(v asn1.RawValue) string {
	// For compound structures, show element count
	if v.IsCompound {
		children, _ := parseASN1Value(v.Bytes)
		return fmt.Sprintf("(%d elem)", len(children))
	}

	switch v.Tag {
	case asn1.TagBoolean:
		var b bool
		asn1.Unmarshal(v.FullBytes, &b)
		return fmt.Sprintf("%v", b)

	case asn1.TagInteger:
		if len(v.Bytes) == 0 {
			return "0"
		}
		// Try to parse as regular int
		var i int64
		_, err := asn1.Unmarshal(v.FullBytes, &i)
		if err == nil && i >= -1000000 && i <= 1000000 {
			return fmt.Sprintf("%d", i)
		}
		// Large integer - show as big.Int
		num := new(big.Int).SetBytes(v.Bytes)
		if len(v.Bytes) > 0 && v.Bytes[0]&0x80 != 0 {
			// Negative number (two's complement)
			num.Sub(num, new(big.Int).Lsh(big.NewInt(1), uint(len(v.Bytes)*8)))
		}
		if len(v.Bytes) <= 8 {
			return num.String()
		}
		bits := len(v.Bytes) * 8
		preview := hex.EncodeToString(v.Bytes[:min(8, len(v.Bytes))])
		return fmt.Sprintf("(%d bit) %s…", bits, preview)

	case asn1.TagBitString:
		var bs asn1.BitString
		_, err := asn1.Unmarshal(v.FullBytes, &bs)
		if err == nil {
			bits := bs.BitLength
			bytes := bs.Bytes
			preview := hex.EncodeToString(bytes[:min(8, len(bytes))])
			if len(bytes) > 8 {
				preview += "…"
			}
			return fmt.Sprintf("(%d bit) %s", bits, preview)
		}
		return "(invalid bit string)"

	case asn1.TagOctetString:
		if len(v.Bytes) == 0 {
			return "(0 byte)"
		}
		preview := strings.ToUpper(hex.EncodeToString(v.Bytes[:min(16, len(v.Bytes))]))
		if len(v.Bytes) > 16 {
			preview += "…"
		}
		return fmt.Sprintf("(%d byte) %s", len(v.Bytes), preview)

	case asn1.TagNull:
		return ""

	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(v.FullBytes, &oid)
		if err == nil {
			oidStr := oid.String()
			if name := oids.DefaultRegistry.LookupDescription(oidStr); name != "" {
				return fmt.Sprintf("%s %s", oidStr, name)
			}
			return oidStr
		}
		return "(invalid OID)"

	case asn1.TagPrintableString, asn1.TagIA5String, asn1.TagUTF8String,
		asn1.TagNumericString, asn1.TagT61String, asn1.TagGeneralString:
		s := string(v.Bytes)
		if len(s) > 64 {
			s = s[:64] + "…"
		}
		return s

	case asn1.TagUTCTime:
		var t time.Time
		_, err := asn1.Unmarshal(v.FullBytes, &t)
		if err == nil {
			return t.Format("2006-01-02 15:04:05 MST")
		}
		return string(v.Bytes)

	case asn1.TagGeneralizedTime:
		var t time.Time
		_, err := asn1.Unmarshal(v.FullBytes, &t)
		if err == nil {
			return t.Format("2006-01-02 15:04:05 MST")
		}
		return string(v.Bytes)

	default:
		// For context-specific or unknown tags
		if v.Class == 2 { // Context-specific
			children, _ := parseASN1Value(v.Bytes)
			return fmt.Sprintf("(%d elem)", len(children))
		}
		if len(v.Bytes) <= 32 {
			return strings.ToUpper(hex.EncodeToString(v.Bytes))
		}
		return fmt.Sprintf("(%d bytes)", len(v.Bytes))
	}
}

func printASN1Tree(v asn1.RawValue, indent string, isLast bool) {
	// Print current node
	prefix := indent
	if indent != "" {
		if isLast {
			prefix += "└─ "
		} else {
			prefix += "├─ "
		}
	} else {
		prefix = "* "
	}

	tagName := getTagName(v.Tag, v.Class)
	content := formatContent(v)

	if content != "" {
		fmt.Printf("%s%s %s\n", prefix, tagName, content)
	} else {
		fmt.Printf("%s%s\n", prefix, tagName)
	}

	// Print children for compound structures
	if v.IsCompound || v.Tag == asn1.TagSequence || v.Tag == asn1.TagSet || v.Class == 2 {
		children, err := parseASN1Value(v.Bytes)
		if err == nil && len(children) > 0 {
			newIndent := indent
			if indent != "" {
				if isLast {
					newIndent += "   "
				} else {
					newIndent += "│  "
				}
			}

			for i, child := range children {
				printASN1Tree(child, newIndent, i == len(children)-1)
			}
		}
	}
}

// PrintASN1 parses and prints arbitrary ASN.1 DER-encoded data
func PrintASN1(data []byte, indent string) error {
	values, err := parseASN1Value(data)
	if err != nil {
		return fmt.Errorf("failed to parse ASN.1: %w", err)
	}

	for i, v := range values {
		printASN1Tree(v, indent, i == len(values)-1)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

/*
Example usage:

func main() {
	derBytes, err := os.ReadFile("signature.p7m")
	if err != nil {
		panic(err)
	}

	// Print ASN.1
	err = PrintASN1(derBytes, " ")
	if err != nil {
		fmt.Printf("Error parsing ASN.1: %v\n", err)
		return
	}

}
*/
