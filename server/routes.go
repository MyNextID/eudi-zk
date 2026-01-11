package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/mynextid/eudi-zk/server/api"
	crlservice "github.com/mynextid/eudi-zk/server/crl-service"
)

// Router Setup
func setupRouter(server *api.Server, cfg *Config, logger Logger) *chi.Mux {
	r := chi.NewRouter()

	// Core middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(loggerMiddleware(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(cfg.WriteTimeout))
	r.Use(middleware.RequestSize(cfg.MaxRequestSize))

	// CORS middleware
	if cfg.EnableCORS {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   cfg.CorsOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Content-Type"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	// Compression
	r.Use(middleware.Compress(5))

	// Discovery information
	r.Get("/", server.HandleDiscovery)

	// Health and readiness
	r.Get("/health", server.HandleHealth)

	// Circuit info
	r.Get("/circuits", server.HandleListCircuits)
	r.Get("/circuits/{circuit}", server.HandleGetCircuit)
	r.Get("/circuits/{circuit}/id", server.HandleGetCircuitID)

	// Proof operations
	r.Post("/prove/{circuit}", server.HandleProve)
	r.Post("/verify/{circuit}", server.HandleVerify)

	// CRL Service routes
	crlStore := crlservice.NewStore()
	crlConfig := crlservice.DefaultConfig()
	crlCA, err := crlservice.NewCAManager()
	if err != nil {
		logger.Error("Failed to initialize CRL CA", "error", err)
		// Handle error appropriately
		panic(err)
	}

	crlSvc := crlservice.NewCRLService(crlStore, crlConfig, crlCA)
	crlHandler := crlservice.NewCRLHandler(crlSvc)

	// Mount CRL routes under /status prefix
	r.Route("/crl-services", func(r chi.Router) {
		// Add caching and rate-limiting later
		// r.Use(crlservice.CacheControlMiddleware(1 * time.Hour))

		// Register all CRL routes
		crlservice.RegisterRoutes(r, crlHandler)
	})

	// Pprof (debug only)
	// if cfg.EnablePprof {
	// 	r.Mount("/debug", middleware.Profiler())
	// }

	return r
}
