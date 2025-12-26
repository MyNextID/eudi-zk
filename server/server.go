package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mynextid/eudi-zk/server/api"
)

type ServeConfig struct {
	// Server settings
	Host string
	Port int

	// Circuit settings
	CircuitsDir string
	Circuits    []string // Specific circuits to load (empty = all)

	// Performance settings
	MaxRequestSize  int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Security settings
	EnableCORS  bool
	CorsOrigins []string

	// Observability
	EnablePprof bool
	LogLevel    string
	LogFormat   string // "json" or "text"

	// TLS settings
	EnableTLS bool
	CertFile  string
	KeyFile   string
}

func Run(cfg *ServeConfig) error {
	// Validate configuration
	if err := validateServeConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Setup structured logging
	logger := SetupLogger(cfg.LogLevel, cfg.LogFormat)

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
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	httpServer := &http.Server{
		Addr:           addr,
		Handler:        r,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Server listening", "addr", addr, "tls", cfg.EnableTLS)

		var err error
		if cfg.EnableTLS {
			err = httpServer.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
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
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	logger.Info("Shutting down server gracefully...")
	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Info("Server stopped")
	return nil
}

func loadCircuits(registry *api.CircuitRegistry, cfg *ServeConfig, logger Logger) error {
	circuitsToLoad := cfg.Circuits
	if len(circuitsToLoad) == 0 {
		// Load all circuits
		for name := range api.CircuitList {
			circuitsToLoad = append(circuitsToLoad, name)
		}
	}

	loaded := 0
	for _, name := range circuitsToLoad {
		ci := api.CircuitList[name]
		ci.Dir = cfg.CircuitsDir

		if err := registry.LoadCircuit(ci); err != nil {
			logger.Warn("Failed to load circuit", "circuit", name, "error", err)
			continue
		}
		loaded++
		logger.Info("Loaded circuit", "circuit", name)
	}

	if loaded == 0 {
		return fmt.Errorf("no circuits loaded from %s", cfg.CircuitsDir)
	}

	logger.Info("Circuit loading complete", "loaded", loaded, "total", len(circuitsToLoad))
	return nil
}

func validateServeConfig(cfg *ServeConfig) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.Port)
	}

	if cfg.EnableTLS {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert-file or key-file not provided")
		}
		if _, err := os.Stat(cfg.CertFile); err != nil {
			return fmt.Errorf("cert file not found: %s", cfg.CertFile)
		}
		if _, err := os.Stat(cfg.KeyFile); err != nil {
			return fmt.Errorf("key file not found: %s", cfg.KeyFile)
		}
	}

	if _, err := os.Stat(cfg.CircuitsDir); err != nil {
		return fmt.Errorf("circuits directory not found: %s", cfg.CircuitsDir)
	}

	return nil
}
