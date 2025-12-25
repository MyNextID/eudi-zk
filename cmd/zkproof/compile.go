package zkproof

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mynextid/eudi-zk/server/api"
	"github.com/spf13/cobra"
)

type compileConfig struct {
	outputDir string
	circuits  []string
	curve     string
	force     bool
}

func NewCompileCmd() *cobra.Command {
	cfg := &compileConfig{}

	cmd := &cobra.Command{
		Use:   "compile",
		Short: "Compile circuits and generate setup files",
		Long:  `Compile zero-knowledge circuits and generate constraint systems, proving keys, and verification keys. Compiling all circuits might take some time. List of circuits is available available at server/api/list.go`,
		Example: `  # Compile all circuits
  zkproof compile -o ./setup

  # Compile specific circuits
  zkproof compile -o ./setup -c compare-bytes-b64url,compare-bytes

`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompile(cfg)
		},
	}

	cmd.Flags().StringVarP(&cfg.outputDir, "output", "o", "./setup", "Output directory for compiled circuits")
	cmd.Flags().StringSliceVarP(&cfg.circuits, "circuits", "c", []string{}, "Specific circuits to compile (comma-separated, empty = all)")
	cmd.Flags().StringVar(&cfg.curve, "curve", "bn254", "Elliptic curve (bn254)")
	cmd.Flags().BoolVarP(&cfg.force, "force", "f", false, "Overwrite existing files")

	return cmd
}

func runCompile(cfg *compileConfig) error {
	// Create output directory
	if err := os.MkdirAll(cfg.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	circuitsToCompile := cfg.circuits
	if len(circuitsToCompile) == 0 {
		for name := range api.CircuitList {
			circuitsToCompile = append(circuitsToCompile, name)
		}
	}

	fmt.Printf("\n==== Compiling %d circuits to %s====\n", len(circuitsToCompile), cfg.outputDir)

	for _, name := range circuitsToCompile {
		info, ok := api.CircuitList[name]
		if !ok {
			fmt.Printf("Circuit %s not found, skipping\n", name)
			continue
		}

		start := time.Now()
		fmt.Printf("Compiling %s...\n", name)

		ccsPath := filepath.Join(cfg.outputDir, fmt.Sprintf("%s.ccs", name))
		pkPath := filepath.Join(cfg.outputDir, fmt.Sprintf("%s.pk", name))
		vkPath := filepath.Join(cfg.outputDir, fmt.Sprintf("%s.vk", name))

		// Check if files exist
		if !cfg.force {
			if _, err := os.Stat(ccsPath); err == nil {
				fmt.Printf("%s already exists, skipping (use --force to overwrite)\n", name)
				continue
			}
			if _, err := os.Stat(pkPath); err == nil {
				fmt.Printf("%s already exists, skipping (use --force to overwrite)\n", pkPath)
				continue
			}
			if _, err := os.Stat(vkPath); err == nil {
				fmt.Printf("%s already exists, skipping (use --force to overwrite)\n", vkPath)
				continue
			}
		}

		// set the output dir
		info.Dir = cfg.outputDir

		// compile the circuit
		if err := info.Compile(); err != nil {
			fmt.Printf("[X] Failed to compile %s: %v\n", name, err)
			continue
		}

		elapsed := time.Since(start)
		fmt.Printf("[OK] Compiled %s in %s\n", name, elapsed.Round(time.Second))
	}

	fmt.Println("\n==== Compilation complete ====")
	return nil
}
