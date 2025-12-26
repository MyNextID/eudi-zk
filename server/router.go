package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/mynextid/eudi-zk/server/api"
)

func setupRouter(server *api.Server, cfg *ServeConfig, logger Logger) *chi.Mux {
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
			AllowedMethods:   []string{"GET", "POST"},
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
	if cfg.EnablePprof {
		r.Mount("/debug", middleware.Profiler())
	}

	return r
}
