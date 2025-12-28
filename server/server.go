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

// Constants
const (
	MaxRequestSize  = 10 * 1024 * 1024
	MaxHeaderSize   = 1 * 1024 * 1024
	ReadTimeout     = 15 * time.Second
	WriteTimeout    = 120 * time.Second
	IdleTimeout     = 120 * time.Second
	ShutdownTimeout = 30 * time.Second
)

// Config contains the server configuration parameters
type Config struct {
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

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *Config {
	return &Config{
		Host:            "localhost",
		Port:            8080,
		CircuitsDir:     "setup",
		Circuits:        []string{},
		MaxRequestSize:  MaxRequestSize,
		ReadTimeout:     ReadTimeout,
		WriteTimeout:    WriteTimeout,
		IdleTimeout:     IdleTimeout,
		ShutdownTimeout: ShutdownTimeout,
		EnableCORS:      true,
		CorsOrigins:     []string{"localhost"},
		EnablePprof:     false,
		LogLevel:        "info",
		LogFormat:       "text",
		EnableTLS:       false,
		CertFile:        "",
		KeyFile:         "",
	}
}

// Run validates the configuration and starts the HTTP server
func Run(cfg *Config) error {
	// Validate server configuration
	if err := validateServerConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Setup structured logging
	logger := SetupLogger(cfg.LogLevel, cfg.LogFormat)

	// Initialize circuit registry
	registry, err := api.NewCircuitRegistry(cfg.CircuitsDir)
	if err != nil {
		return err
	}

	// Initialize HTTP server
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
		MaxHeaderBytes: MaxHeaderSize,
	}

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		fmt.Println("[HTTP Server] server starting at:", addr)
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

// validateServe
func validateServerConfig(cfg *Config) error {
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
