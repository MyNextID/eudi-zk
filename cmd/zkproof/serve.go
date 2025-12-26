package zkproof

import (
	"time"

	"github.com/mynextid/eudi-zk/server"
	"github.com/spf13/cobra"
)

func NewServeCmd() *cobra.Command {
	cfg := &server.ServeConfig{}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the ZK proof API server",
		Long:  `Start the HTTP API server for generating and verifying zero-knowledge proofs.`,
		Example: `  # Start server on default port zkproof serve

  # Start with custom settings
  zkproof serve --host 0.0.0.0 --port 9090 --circuits-dir ./setup

  # Production deployment with TLS
  zkproof serve --host 0.0.0.0 --port 443 --enable-tls \
    --cert-file /etc/ssl/cert.pem --key-file /etc/ssl/key.pem

  # Load specific circuits only
  zkproof serve --circuits compare-bytes-b64url,compare-bytes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(cfg)
		},
	}

	// Server flags
	cmd.Flags().StringVar(&cfg.Host, "host", "localhost", "Host to bind to")
	cmd.Flags().IntVarP(&cfg.Port, "port", "p", 8080, "Port to listen on")

	// Circuit flags
	cmd.Flags().StringVarP(&cfg.CircuitsDir, "circuits-dir", "d", "./setup", "Directory containing compiled circuits")
	cmd.Flags().StringSliceVarP(&cfg.Circuits, "circuits", "c", []string{}, "Specific circuits to load (comma-separated, empty = all)")

	// Performance flags
	cmd.Flags().Int64Var(&cfg.MaxRequestSize, "max-request-size", 10*1024*1024, "Maximum request body size in bytes")
	cmd.Flags().DurationVar(&cfg.ReadTimeout, "read-timeout", 15*time.Second, "HTTP read timeout")
	cmd.Flags().DurationVar(&cfg.WriteTimeout, "write-timeout", 120*time.Second, "HTTP write timeout (proof generation can be slow)")
	cmd.Flags().DurationVar(&cfg.IdleTimeout, "idle-timeout", 120*time.Second, "HTTP idle timeout")
	cmd.Flags().DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", 30*time.Second, "Graceful shutdown timeout")

	// Security flags
	cmd.Flags().BoolVar(&cfg.EnableCORS, "enable-cors", true, "Enable CORS middleware")
	cmd.Flags().StringSliceVar(&cfg.CorsOrigins, "cors-origins", []string{"*"}, "Allowed CORS origins")

	// Observability flags
	cmd.Flags().BoolVar(&cfg.EnablePprof, "enable-pprof", false, "Enable pprof endpoints (debug only)")
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", "text", "Log format (text, json)")

	// TLS flags
	cmd.Flags().BoolVar(&cfg.EnableTLS, "enable-tls", false, "Enable TLS/HTTPS")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", "", "TLS certificate file")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", "", "TLS private key file")

	return cmd
}
