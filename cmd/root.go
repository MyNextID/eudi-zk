package main

import (
	"fmt"

	"github.com/mynextid/eudi-zk/cmd/zkproof"
	"github.com/spf13/cobra"
)

// Init the cmd
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "zkpi",
		Short: "Zero-Knowledge Proof Interfaces",
		Long: `
  A collection of tools and APIs for creating and verifying zero-knowledge
  proofs for EUDI digital identity and privacy-preserving applications.`,
	}

	rootCmd.AddCommand(
		zkproof.NewServeCmd(),
		zkproof.NewCompileCmd(),
		NewVersionCmd(),
	)

	return rootCmd
}

func addFooter(cmd *cobra.Command) {
	originalHelp := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		originalHelp(c, args)
		fmt.Println("\n" + buildFooter())
	})
}

func buildFooter() string {
	return `────────────────────────────────────────────────────────────────────────────────

ONLINE DOCUMENTATION
  https://github.com/MyNextID/eudi-zk

COPYRIGHT
  (c) 2025 MyNextID/Netis d.o.o.

LICENSE
  Licensed under MIT

FEEDBACK
  Your feedback is valuable! The ZKPI utility does not collect usage statistics
  or phone home. Please share your experience, suggestions, or issues:
  
  - GitHub Issues: https://github.com/MyNextID/eudi-zk/issues
  - Email: info@mynext.id

────────────────────────────────────────────────────────────────────────────────`
}
