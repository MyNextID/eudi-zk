package main

import (
	"fmt"
	"os"
)

// ZKPI - simple CLI tool and API service for Zero-Knowledge proof generation
// and validation
func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
