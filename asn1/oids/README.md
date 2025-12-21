# OIDs Parser and Registry

A GO package for parsing and working with Object Identifiers from the
[dumpasn1.cfg](https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg) file.

## Features

- Parse `dumpasn1.cfg` format files
- Fast O(1) OID lookups via map
- Build-time generation with `go:generate` for zero runtime parsing cost

## Installation

```bash
go get github.com/mynextid/oids
```

## Usage

### Option 1: Runtime Parsing

Parse the config file at runtime:

```go
package main

import (
    "fmt"
    "log"
    "os"
    
    "yourmodule/oids"
)

func main() {
    f, err := os.Open("dumpasn1.cfg")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    
    registry, err := oids.ParseFile(f)
    if err != nil {
        log.Fatal(err)
    }
    
    // Lookup an OID
    info, found := registry.Lookup("1.2.840.113549.1.1.1")
    if found {
        fmt.Printf("OID: %s\n", info.OID)
        fmt.Printf("Description: %s\n", info.Description)
        if info.Comment != "" {
            fmt.Printf("Comment: %s\n", info.Comment)
        }
        if info.Warning {
            fmt.Printf("WARNING: This OID should trigger a warning\n")
        }
    }
    
    // Quick description lookup
    desc := registry.LookupDescription("2.5.4.3")
    fmt.Println("Common Name OID:", desc)
    
    fmt.Printf("Total OIDs loaded: %d\n", registry.Count())
}
```

### Option 2: Build-time Generation

Recommended for Production

Generate the registry at build time for zero runtime overhead:

**Step 1:** Add to your `oids.go` file:

```go
package oids

//go:generate go run generate.go
```

**Step 2:** Download the config file:

```bash
wget https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
```

**Step 3:** Copy `generate.go` to your package directory

**Step 4:** Generate the code:

```bash
go generate ./
```

This creates `oids_generated.go` with a pre-populated `DefaultRegistry`.

**Step 5:** Use the default registry:

```go
package main

import (
    "fmt"
    "github.com/mynextid/oids"
)

func main() {
    // No parsing needed - registry is already loaded!
    info, found := oids.DefaultRegistry.Lookup("1.2.840.113549.1.1.1")
    if found {
        fmt.Println(info.Description)
    }
    
    // Quick description lookup
    desc := oids.DefaultRegistry.LookupDescription("2.5.4.3")
    fmt.Println("Description:", desc)
}
```

## Testing

Run tests:

```bash
go test ./oids -v
```

Test with the real dumpasn1.cfg file:

```bash
wget https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
go test ./oids -v
```

## Credits

The dumpasn1.cfg file is maintained by Peter Gutmann.

Source: [dumpasn1.cfg](https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg)
