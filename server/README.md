# ZKPI - Easy Zero Knowledge Proof creation and validation

A simple CLI tool and HTTP API service for generating and verifying
zero-knowledge proofs.

## Features

- HTTP API - RESTful API for easy testing
- CLI Tools - Command-line interface for circuit management
- Multiple Circuits - Support for various proof types
- OpenAPI Spec - Auto-generated API documentation (in progress)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mynextid/eudi-zk.git
cd eudi-zk/

# Build the binary
make build

# The binary will be available at ./bin/zkpi
./bin/zkpi --help
```

## Install to GOPATH

```bash
make install
zkpi --help
```

## Basic Usage

### 1. Compile Circuits

First, compile the zero-knowledge circuits:

```bash
zkpi compile -o ./setup
```

This generates three files for each circuit:

- `.ccs` - Constraint system
- `.pk` - Proving key
- `.vk` - Verification key

### 2. Validate Setup

Verify that all circuit files are present and valid:

```bash
zkpi validate -d ./setup
```

### 3. Start the API Server

```bash
zkpi serve --circuits-dir ./setup
```

The server will start on `http://localhost:8080`

## CLI Commands

### `zkpi serve`

Start the HTTP API server.

```bash
zkpi serve [flags]

Flags:
  # Server Configuration
  --host string              Host to bind to (default "localhost")
  -p, --port int             Port to listen on (default 8080)
  
  # Circuit Configuration
  -d, --circuits-dir string  Directory containing compiled circuits (default "./setup")
  -c, --circuits strings     Specific circuits to load (comma-separated, empty = all)
```

**Examples:**

```bash
# Development mode
zkpi serve

# Load specific circuits only
zkpi serve --circuits compare-bytes-b64url,compare-bytes
```

### `zkpi compile`

Compile circuits and generate setup files.

```bash
zkpi compile [flags]

Flags:
  -o, --output string       Output directory for compiled circuits (default "./setup")
  -c, --circuits strings    Specific circuits to compile (comma-separated, empty = all)
  --curve string           Elliptic curve: bn254, bls12-381 (default "bn254")
  --parallel int           Number of parallel compilation jobs (default 1)
  -f, --force              Overwrite existing files
```

**Examples:**

```bash
# Compile all circuits
zkpi compile -o ./setup

# Compile specific circuits
zkpi compile -o ./setup -c compare-bytes-b64url,compare-bytes

# Parallel compilation
zkpi compile -o ./setup --parallel 4

# Force recompilation
zkpi compile -o ./setup --force
```

## HTTP API

### Endpoints

#### Health Check

```http
GET /health
```

Returns server health status.

#### List Circuits

```http
GET /circuits
```

Returns a list of all available circuits.

#### Get Circuit Info

```http
GET /circuits/{circuit}
```

Returns detailed information about a specific circuit.

#### Generate Proof

```http
POST /prove/{circuit}
Content-Type: application/json

{
  "public_input": {
    "bytes_b64": [72, 101, 108, 108, 111]
  },
  "private_input": {
    "bytes": [72, 101, 108, 108, 111]
  }
}
```

**Response:**

```json
{
  "proof": "base64_encoded_proof_string",
  "circuit": "compare-bytes-b64url",
  "timestamp": "2025-12-25T10:30:00Z"
}
```

#### Verify Proof

```http
POST /verify/{circuit}
Content-Type: application/json

{
  "public_input": {
    "bytes_b64": [72, 101, 108, 108, 111]
  },
  "proof": "base64_encoded_proof_string"
}
```

**Response:**

```json
{
  "valid": true,
  "circuit": "compare-bytes-b64url",
  "timestamp": "2025-12-25T10:30:00Z",
  "message": "proof is valid"
}
```

#### OpenAPI Specification

```http
GET /openapi.json
```

Returns the complete OpenAPI 3.0 specification.

### API Examples

#### Using cURL

```bash
# Generate a proof
curl -X POST http://localhost:8080/prove/compare-bytes-b64url \
  -H "Content-Type: application/json" \
  -d '{
    "public_input": {
      "bytes_b64": [72, 101, 108, 108, 111]
    },
    "private_input": {
      "bytes": [72, 101, 108, 108, 111]
    }
  }'

# Verify a proof
curl -X POST http://localhost:8080/verify/compare-bytes-b64url \
  -H "Content-Type: application/json" \
  -d '{
    "public_input": {
      "bytes_b64": [72, 101, 108, 108, 111]
    },
    "proof": "YOUR_BASE64_PROOF_HERE"
  }'
```

## Development

### Prerequisites

- Go 1.21 or higher
- Make

### Building from Source

```bash
# Clone the repository
git clone https://github.com/mynextid/eudi-zk.git
cd eudi-zk

# Build
make build

# Run tests
go test ./...

# Install locally
make install
```
