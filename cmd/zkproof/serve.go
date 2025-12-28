package zkproof

import (
	"github.com/mynextid/eudi-zk/server"
	"github.com/spf13/cobra"
)

// NewServeCmd creates the serve command
func NewServeCmd() *cobra.Command {
	cfg := &server.Config{}

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the ZKPI server",
		Long: `
  Starts HTTP API server for creating and verifying zero-knowledge proofs`,
		Example: `  # Start ZKPI on localhost and default port 8080
  zkpi serve

  # Start with custom settings
  zkpi serve --host 0.0.0.0 --port 9090 --circuits-dir circuits

  # Production deployment with TLS
  zkpi serve --host 0.0.0.0 --port 443 --enable-tls \
    --cert-file /etc/ssl/cert.pem --key-file /etc/ssl/key.pem

  # Load specific circuits only
  zkpi serve --circuits compare-bytes-b64url,compare-bytes`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return server.Run(cfg)
		},
	}

	defaultCfg := server.DefaultServerConfig()

	// Server flags
	cmd.Flags().StringVar(&cfg.Host, "host", defaultCfg.Host, "Host to bind to")
	cmd.Flags().IntVarP(&cfg.Port, "port", "p", defaultCfg.Port, "Port to listen on")

	// Circuit flags
	cmd.Flags().StringVarP(&cfg.CircuitsDir, "circuits-dir", "d", defaultCfg.CircuitsDir, "Directory containing compiled circuits")
	cmd.Flags().StringSliceVarP(&cfg.Circuits, "circuits", "c", defaultCfg.Circuits, "Specific circuits to load (comma-separated, empty = all)")

	// Performance flags
	cmd.Flags().Int64Var(&cfg.MaxRequestSize, "max-request-size", defaultCfg.MaxRequestSize, "Maximum request body size in bytes")
	cmd.Flags().DurationVar(&cfg.ReadTimeout, "read-timeout", defaultCfg.ReadTimeout, "HTTP read timeout")
	cmd.Flags().DurationVar(&cfg.WriteTimeout, "write-timeout", defaultCfg.WriteTimeout, "HTTP write timeout (proof generation can be slow)")
	cmd.Flags().DurationVar(&cfg.IdleTimeout, "idle-timeout", defaultCfg.IdleTimeout, "HTTP idle timeout")
	cmd.Flags().DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "Graceful shutdown timeout")

	// Security flags
	cmd.Flags().BoolVar(&cfg.EnableCORS, "enable-cors", defaultCfg.EnableCORS, "Enable CORS middleware")
	cmd.Flags().StringSliceVar(&cfg.CorsOrigins, "cors-origins", defaultCfg.CorsOrigins, "Allowed CORS origins")

	// Observability flags
	// cmd.Flags().BoolVar(&cfg.EnablePprof, "enable-pprof", false, "Enable pprof endpoints (debug only)")
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", defaultCfg.LogLevel, "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", defaultCfg.LogFormat, "Log format (text, json)")

	// TLS flags
	cmd.Flags().BoolVar(&cfg.EnableTLS, "enable-tls", defaultCfg.EnableTLS, "Enable TLS/HTTPS")
	cmd.Flags().StringVar(&cfg.CertFile, "cert-file", defaultCfg.CertFile, "TLS certificate file")
	cmd.Flags().StringVar(&cfg.KeyFile, "key-file", defaultCfg.KeyFile, "TLS private key file")

	return cmd
}
