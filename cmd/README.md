# ZKPI - Easy Zero Knowledge Proof creation and validation

A simple CLI tool and HTTP API server for generating and verifying
zero-knowledge proofs.

## Features

- HTTP API - RESTful API for easy testing
- CLI Tools - Command-line interface for circuit management
- Multiple Circuits - Support for various proof types

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

Note: it will take a while.

This generates three files for each circuit:

- `.ccs` - Constraint system
- `.pk` - Proving key
- `.vk` - Verification key

### 2. Start the API Server

```bash
zkpi serve
```

The server will start on `http://localhost:8080`

## HTTP API

Information about the endpoints is available at the root `http://localhost:8080/`
