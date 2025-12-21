# ASN.1 DER Parser and Pretty Printer

A simple Go package for parsing and visualizing ASN.1 DER-encoded data
structures with a clean tree-based output.

Inspired by [asn1js](https://lapo.it/asn1js/)

## Features

- Parse arbitrary ASN.1 DER-encoded data
- Pretty-print ASN.1 structures as an indented tree
- Automatic OID name resolution (see [OIDs](./oids/README.md))
- Formatting for common data types (integers, strings, dates, bit strings, etc.)
- Support for ASN.1 universal tags and context-specific tags

## Installation

```bash
go get github.com/mynextid/asn1
```

## Usage

```go
package main

import (
    "os"
    "github.com/mynextid/asn1"
)

func main() {
    // Read DER-encoded file (e.g., .p7m, .der, .cer)
    derBytes, err := os.ReadFile("signature.p7m")
    if err != nil {
        panic(err)
    }

    // Print the ASN.1 structure
    err = asn1.PrintASN1(derBytes, " ")
    if err != nil {
        panic(err)
    }
}
```

## Output Example

The parser produces a clean tree visualization:

```text
* SEQUENCE (3 elem)
 ├─ OBJECT IDENTIFIER 1.2.840.113549.1.7.2 pkcs7-signedData
 ├─ [0] (1 elem)
 │  └─ SEQUENCE (4 elem)
 │     ├─ INTEGER 1
 │     ├─ SET (1 elem)
 │     │  └─ SEQUENCE (2 elem)
 │     │     ├─ OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256
 │     │     └─ NULL
 │     ├─ SEQUENCE (2 elem)
 │     │  ├─ OBJECT IDENTIFIER 1.2.840.113549.1.7.1 pkcs7-data
 │     │  └─ [0] (1 elem)
 │     │     └─ OCTET STRING (47 byte) 546869732069732074686520...
 ...
```

## Data Type Formatting

The parser formats different ASN.1 types:

- **INTEGERS**: Displayed as decimal (with bit length for large values)
- **BIT STRINGS**: Shows bit length and hex preview
- **OCTET STRINGS**: Shows byte length and hex preview
- **OIDs**: Displays numeric OID with resolved name (when available)
- **Strings**: UTF8, PrintableString, IA5String, etc. shown as text
- **Times**: UTCTime and GeneralizedTime formatted as readable dates
- **Sequences/Sets**: Shows element count and nested structure

## License

MIT
