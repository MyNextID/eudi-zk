# ZK Circuits

This directory contains reference implementations of zero-knowledge proof
circuits relevant for digital identity frameworks, such as eIDAS, EUDI, and
other. These circuits prioritize clarity and educational value over performance
optimization.

Notes:

- Production-optimized circuits will be published separately
- Some circuits take a while to compile/setup
- Observation: memory consumption of some circuits is high

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

## Circuit collections

### 1. Basic circuits

**Location:** [basic-circuits/](./basic-circuits/README.md)

These circuits implement basic ZK proofs. Our goal is to showcase the basic
logic and operations that will later act as building blocks for more complex ZK
circuits.

### 2. Temporal

**Location:** [temporal](./temporal/README.md)

These circuits provide zero-knowledge proofs for temporal validity constraints
in verifiable credentials and certificates. They enable privacy-preserving
verification of time-based claims (such as age requirements) without revealing
the actual dates or credential contents.

### 3. eIDAS Signature Verification

**Location:** [verifyjwscert/](./verify-jws-cert/README.md)

This construction enables a prover to establish that "a document carries a valid
digital signature from an entity whose public key certificate was issued by a
trusted QTSP," while simultaneously concealing:

- The specific identity of the signing entity
- The complete contents of their certificate
- Metadata about the signature algorithm and keys

### 4. VC Verification

**Location:** [eudi-vc](./eudi-vc/README.md)

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
├── README.md                       # this file
├── {circuit-collection}/           # A collection of circuit implementations
│   ├── README.md                   # Circuit collection summary
│   └── {circuit-name}/             # Circuit implementation and tests
│       ├── {circuit-name}.go       # Circuit implementation
│       ├── {circuit-name}_test.go  # Circuit test(s)
│       └── /examples               # API payload example
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
cd circuits
go test -v -timeout 30m ./...
```

Note: Each test compiles the circuit and initializes the ZK proving system
independently. Expect the complete test suite to take significant time.

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
go test -v -timeout 5m ./basic-circuits
```

### View Available Tests

List all test functions in a circuit:

```bash
go test -list . ./basic-circuits
```

## Troubleshooting

### Compilation Takes Too Long

Circuit compilation is computationally intensive. If tests timeout:

```bash
go test -v -timeout 15m ./basic-circuits
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

1. **Explore examples:** Start with `basic-circuits/` for basic patterns
2. **Read circuit docs:** Check each folder's README.md for detailed explanations
3. **Run tests:** Execute tests to see circuits in action
4. **Modify inputs:** Edit test functions to experiment with different values
5. **Build new circuits:** Use existing circuits as templates

## Performance Notes

- **First run:** Compilation generates CCS and keys (slow, 1-5 minutes)
- **Subsequent runs:** Uses cached artifacts (fast, seconds)
- **Constraint count:** Check test output for circuit complexity metrics
