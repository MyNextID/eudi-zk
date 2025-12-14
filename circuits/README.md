# ZK Circuits

This directory contains reference implementations of zero-knowledge proof
circuits for eIDAS and EUDI use cases. These circuits prioritize clarity and
educational value over performance optimization.

**Note:** Production-optimized circuits will be published separately.

## Prerequisites

### Required Software

1. Go 1.24.2 or higher
   - Download: <https://go.dev/doc/install>
   - Verify installation: `go version`

2. Git (for cloning the repository)
   - Verify installation: `git --version`

### Clone the Repository

```bash
git clone https://github.com/MyNextID/eudi-zk.git
cd eudi-zk/circuits
```

### Install Dependencies

```bash
go mod download
```

This will install [Gnark v0.14](https://pkg.go.dev/github.com/consensys/gnark)
and all required dependencies.

## Tested Cryptography & Encodings

**Elliptic Curves:**

- secp256r1 (P-256) - commonly used in eIDAS certificates

**Hash Functions:**

- SHA-256

**Encodings:**

- DER (Distinguished Encoding Rules) - X.509 certificate format
- Hexadecimal
- Base64URL
- JWT/JWS signature formats (common on the web)

## Available Circuits

### 1. Compare Bytes

**Location:** [compare-bytes/](./compare-bytes/)

Basic circuits demonstrating fundamental operations like byte comparison, public key encoding, and digest matching.

### 2. Key Binding

**Location:** [key-binding/](./key-binding/)

Circuits for validating Verifiable Credential holder key binding using different approaches:

- cnf (Confirmation Method) validation
- Key digest verification

### 3. eIDAS Signature Verification

**Location:** [verify-eidas-signature/](./verify-eidas-signature/)

Circuits for validating digital signatures in eIDAS contexts:

- JWS (JSON Web Signature) validation
- DER-encoded signature verification

### 4. VC Verification

**Location:** [der-x509-lookup](./der-x509-lookup/README.md)

Circuits for validating VC signatures and holder binging proofs

- I (subject/holder) have a certificate with a subject public key
- I can sign a challenge with the private key corresponding to that public key
- My certificate signature is verified with the public key of the CA/QTSP(public input)
- VC signature is verified with the public key of the issuer (public input)
- VC contains the my (subject's) public key
- Without revealing the certificate or the public key

## Repository Structure

Each circuit folder follows this organization:

```bash
circuits/
├── {circuit-name}/
│   ├── README.md              # Circuit-specific documentation
│   ├── circuit_test.go        # Test functions and examples
│   ├── {circuit-name}.go      # Circuit implementation
│   └── compiled/              # Generated artifacts (gitignored)
│       ├── circuit.ccs        # Constraint system
│       ├── proving.key        # Proving key
│       └── verification.key   # Verifier key
```

## Running the Circuits

### Quick Start

Navigate to the circuits directory:

```bash
cd circuits
```

### Run All Tests

Execute all circuit tests:

```bash
go test -v -timeout 5m ./...
```

### Run Specific Circuit

Test a specific circuit using its import path:

```bash
go test -v -timeout 5m -run ^TestCompareDigestPubKeys$ github.com/mynextid/eudi-zk/circuits/compare-bytes
```

**Command breakdown:**

- `-v`: Verbose output (shows test progress)
- `-timeout 5m`: Sets 5-minute timeout (circuit compilation can be slow)
- `-run ^TestName$`: Runs specific test function matching the regex pattern
- Final argument: Full import path to the circuit package

### Run All Tests in a Circuit Folder

```bash
go test -v -timeout 5m ./compare-bytes
```

### View Available Tests

List all test functions in a circuit:

```bash
go test -list . ./compare-bytes
```

## Troubleshooting

### Compilation Takes Too Long

Circuit compilation is computationally intensive. If tests timeout:

```bash
go test -v -timeout 15m ./compare-bytes
```

### Missing Dependencies

If you encounter import errors:

```bash
go mod tidy
go mod download
```

### Clean Compiled Artifacts

Remove generated files to recompile from scratch:

```bash
rm -rf */compiled/*
```

## Development Workflow

1. **Explore examples:** Start with `compare-bytes/` for basic patterns
2. **Read circuit docs:** Check each folder's README.md for detailed explanations
3. **Run tests:** Execute tests to see circuits in action
4. **Modify inputs:** Edit test functions to experiment with different values
5. **Build new circuits:** Use existing circuits as templates

## Performance Notes

- **First run:** Compilation generates CCS and keys (slow, 1-5 minutes)
- **Subsequent runs:** Uses cached artifacts (fast, seconds)
- **Constraint count:** Check test output for circuit complexity metrics

If you're modifying only the inputs, set `forceCompile := false`.
