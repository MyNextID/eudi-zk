// Package main implements the command line and the API service
package main

import (
	"fmt"
	"os"
)

// ZKPI - a simple CLI tool and API service for Zero-Knowledge proof creation
// and validation
func main() {
	rootCmd := newRootCmd()

	// Optional: Add footer to help output
	addFooter(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
