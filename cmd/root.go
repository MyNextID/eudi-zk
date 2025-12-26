package main

import (
	"github.com/mynextid/eudi-zk/cmd/zkproof"
	"github.com/spf13/cobra"
)

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
