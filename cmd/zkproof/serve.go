package zkproof

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/mynextid/eudi-zk/server/api"
	"github.com/spf13/cobra"
)

type serveConfig struct {
	// Server settings
	host string
	port int

	// Circuit settings
	circuitsDir string
	circuits    []string // Specific circuits to load (empty = all)

	// Performance settings
	maxRequestSize  int64
	readTimeout     time.Duration
	writeTimeout    time.Duration
	idleTimeout     time.Duration
	shutdownTimeout time.Duration

	// Security settings
	enableCORS  bool
	corsOrigins []string

	// Observability
	enablePprof bool
	logLevel    string
	logFormat   string // "json" or "text"

	// TLS settings
	enableTLS bool
	certFile  string
	keyFile   string
}

func NewServeCmd() *cobra.Command {
	cfg := &serveConfig{}

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
			return runServe(cfg)
		},
	}

	// Server flags
	cmd.Flags().StringVar(&cfg.host, "host", "localhost", "Host to bind to")
	cmd.Flags().IntVarP(&cfg.port, "port", "p", 8080, "Port to listen on")

	// Circuit flags
	cmd.Flags().StringVarP(&cfg.circuitsDir, "circuits-dir", "d", "./setup", "Directory containing compiled circuits")
	cmd.Flags().StringSliceVarP(&cfg.circuits, "circuits", "c", []string{}, "Specific circuits to load (comma-separated, empty = all)")

	// Performance flags
	cmd.Flags().Int64Var(&cfg.maxRequestSize, "max-request-size", 10*1024*1024, "Maximum request body size in bytes")
	cmd.Flags().DurationVar(&cfg.readTimeout, "read-timeout", 15*time.Second, "HTTP read timeout")
	cmd.Flags().DurationVar(&cfg.writeTimeout, "write-timeout", 120*time.Second, "HTTP write timeout (proof generation can be slow)")
	cmd.Flags().DurationVar(&cfg.idleTimeout, "idle-timeout", 120*time.Second, "HTTP idle timeout")
	cmd.Flags().DurationVar(&cfg.shutdownTimeout, "shutdown-timeout", 30*time.Second, "Graceful shutdown timeout")

	// Security flags
	cmd.Flags().BoolVar(&cfg.enableCORS, "enable-cors", false, "Enable CORS middleware")
	cmd.Flags().StringSliceVar(&cfg.corsOrigins, "cors-origins", []string{"*"}, "Allowed CORS origins")

	// Observability flags
	cmd.Flags().BoolVar(&cfg.enablePprof, "enable-pprof", false, "Enable pprof endpoints (debug only)")
	cmd.Flags().StringVar(&cfg.logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&cfg.logFormat, "log-format", "text", "Log format (text, json)")

	// TLS flags
	cmd.Flags().BoolVar(&cfg.enableTLS, "enable-tls", false, "Enable TLS/HTTPS")
	cmd.Flags().StringVar(&cfg.certFile, "cert-file", "", "TLS certificate file")
	cmd.Flags().StringVar(&cfg.keyFile, "key-file", "", "TLS private key file")

	return cmd
}

func runServe(cfg *serveConfig) error {
	// Validate configuration
	if err := validateServeConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Setup structured logging
	logger := setupLogger(cfg.logLevel, cfg.logFormat)

	// Initialize circuit registry
	registry := api.NewCircuitRegistry()

	// Load circuits
	if err := loadCircuits(registry, cfg, logger); err != nil {
		return fmt.Errorf("failed to load circuits: %w", err)
	}

	// Create server
	server := api.NewServer(registry)

	// Setup router with middleware
	r := setupRouter(server, cfg, logger)

	// Configure HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	httpServer := &http.Server{
		Addr:           addr,
		Handler:        r,
		ReadTimeout:    cfg.readTimeout,
		WriteTimeout:   cfg.writeTimeout,
		IdleTimeout:    cfg.idleTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server listening", "addr", addr, "tls", cfg.enableTLS)

		var err error
		if cfg.enableTLS {
			err = httpServer.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
		} else {
			err = httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for interrupt signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("Shutdown signal received")
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()

	logger.Info("Shutting down server gracefully...")
	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Info("Server stopped")
	return nil
}

func setupRouter(server *api.Server, cfg *serveConfig, logger Logger) *chi.Mux {
	r := chi.NewRouter()

	// Core middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(loggerMiddleware(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(cfg.writeTimeout))
	r.Use(middleware.RequestSize(cfg.maxRequestSize))

	// CORS middleware
	if cfg.enableCORS {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   cfg.corsOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Content-Type"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	// Compression
	r.Use(middleware.Compress(5))

	// Health and readiness
	r.Get("/health", server.HandleHealth)

	// Circuit info
	r.Get("/circuits", server.HandleListCircuits)
	r.Get("/circuits/{circuit}", server.HandleGetCircuit)

	// Proof operations
	r.Post("/prove/{circuit}", server.HandleProve)
	r.Post("/verify/{circuit}", server.HandleVerify)

	// OpenAPI spec
	// r.Get("/openapi.json", server.HandleOpenAPI)

	// Pprof (debug only)
	if cfg.enablePprof {
		r.Mount("/debug", middleware.Profiler())
	}

	return r
}

func loadCircuits(registry *api.CircuitRegistry, cfg *serveConfig, logger Logger) error {
	circuitsToLoad := cfg.circuits
	if len(circuitsToLoad) == 0 {
		// Load all circuits
		for name := range api.CircuitList {
			circuitsToLoad = append(circuitsToLoad, name)
		}
	}

	loaded := 0
	for _, name := range circuitsToLoad {
		ci := api.CircuitList[name]
		ci.Dir = cfg.circuitsDir

		if err := registry.LoadCircuit(ci); err != nil {
			logger.Warn("Failed to load circuit", "circuit", name, "error", err)
			continue
		}
		loaded++
		logger.Info("Loaded circuit", "circuit", name)
	}

	if loaded == 0 {
		return fmt.Errorf("no circuits loaded from %s", cfg.circuitsDir)
	}

	logger.Info("Circuit loading complete", "loaded", loaded, "total", len(circuitsToLoad))
	return nil
}

func validateServeConfig(cfg *serveConfig) error {
	if cfg.port < 1 || cfg.port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.port)
	}

	if cfg.enableTLS {
		if cfg.certFile == "" || cfg.keyFile == "" {
			return fmt.Errorf("TLS enabled but cert-file or key-file not provided")
		}
		if _, err := os.Stat(cfg.certFile); err != nil {
			return fmt.Errorf("cert file not found: %s", cfg.certFile)
		}
		if _, err := os.Stat(cfg.keyFile); err != nil {
			return fmt.Errorf("key file not found: %s", cfg.keyFile)
		}
	}

	if _, err := os.Stat(cfg.circuitsDir); err != nil {
		return fmt.Errorf("circuits directory not found: %s", cfg.circuitsDir)
	}

	return nil
}
