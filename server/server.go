package main

// ZKPI - simple CLI tool and API service for Zero-Knowledge proof generation
// and validation

import (
	"fmt"
	"os"

	"github.com/mynextid/eudi-zk/cmd/zkproof"
	"github.com/spf13/cobra"
)

// version and commit info
// DO NOT EDIT - information is update by the Makefile
var (
	version   = ""
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Init the cmd
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "zkpi",
		Short: "Zero-Knowledge Proof API Server",
		Long:  `A collection of tools and APIs for generating and verifying zero-knowledge proofs`,
	}

	rootCmd.AddCommand(
		zkproof.NewServeCmd(),
		zkproof.NewCompileCmd(),
		NewVersionCmd(),
	)

	return rootCmd
}

// NewVersionCmd returns a version information cmd
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("  version: %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", buildDate)
		},
	}
}
