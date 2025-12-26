package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version and commit info
// DO NOT EDIT - information is update by the Makefile
var (
	version   = ""
	commit    = "none"
	buildDate = "unknown"
)

// NewVersionCmd returns a version information cmd
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Aliases: []string{"v"},
		Short:   "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("  version: %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", buildDate)
		},
	}
}
