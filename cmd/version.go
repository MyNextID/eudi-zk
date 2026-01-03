package main

import (
	"fmt"
	"runtime"

	"github.com/mynextid/eudi-zk/server/api"
	"github.com/spf13/cobra"
)

func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `
  Print detailed version and build information
  
  The version command displays the ZKPI version, build commit, build date, and
  Go runtime information.`,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("  Version:    %s\n", api.Version)
			fmt.Printf("  Commit:     %s\n", api.Commit)
			fmt.Printf("  Built:      %s\n", api.BuildDate)
			fmt.Printf("  Go version: %s\n", runtime.Version())
			fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
