package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"

	"github.com/dqx0/glen/user-service/internal/webauthn"
	"github.com/dqx0/glen/user-service/internal/webauthn/config"
)

// SetupWebAuthnRoutes sets up WebAuthn routes for the user service
func SetupWebAuthnRoutes(r chi.Router, db *sqlx.DB, redisClient *redis.Client) error {
	// Load WebAuthn configuration
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Printf("Warning: Failed to load WebAuthn config from env, using defaults: %v", err)
		cfg = &config.WebAuthnConfig{
			RPDisplayName: "Glen ID Platform",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost:3000", "http://localhost:5173", "https://glen.dqx0.com"},
			RPIcon:        "",
			Timeout:       60000,
			Debug:         true, // Enable debug mode for development
		}
	}

	// For production, override with production URLs
	if cfg.RPID == "localhost" {
		// Check if we're in production environment
		if val := getEnvOrDefault("ENVIRONMENT", "development"); val == "production" {
			cfg.RPID = "glen.dqx0.com"
			cfg.RPOrigins = []string{"https://glen.dqx0.com"}
			cfg.Debug = false
		}
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid WebAuthn configuration: %w", err)
	}

	// Initialize WebAuthn module
	webAuthnModule, err := webauthn.NewWebAuthnModule(db, redisClient, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize WebAuthn module: %w", err)
	}

	// Perform health check
	if err := webAuthnModule.HealthCheck(); err != nil {
		return fmt.Errorf("WebAuthn module health check failed: %w", err)
	}

	// Check database tables
	migration := webauthn.NewDatabaseMigration(db)
	if err := migration.CheckWebAuthnTables(); err != nil {
		log.Printf("WebAuthn tables not found, creating them: %v", err)
		if err := migration.CreateWebAuthnTables(); err != nil {
			return fmt.Errorf("failed to create WebAuthn tables: %w", err)
		}
		log.Println("WebAuthn tables created successfully")
	}

	// Mount WebAuthn routes under /api/v1
	r.Route("/api/v1", func(r chi.Router) {
		webAuthnModule.Handler.RegisterRoutes(r)
	})

	log.Printf("WebAuthn module initialized successfully")
	log.Printf("- RPID: %s", cfg.RPID)
	log.Printf("- Origins: %v", cfg.RPOrigins)
	log.Printf("- Debug: %v", cfg.Debug)

	return nil
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Example of how to integrate with existing user service main function
func ExampleMainIntegration() {
	// This is an example of how to integrate WebAuthn into your main function
	
	/*
	func main() {
		// Initialize database
		db, err := sqlx.Connect("postgres", "your-database-url")
		if err != nil {
			log.Fatal("Failed to connect to database:", err)
		}
		defer db.Close()

		// Initialize Redis
		redisClient := redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		})
		defer redisClient.Close()

		// Initialize router
		r := chi.NewRouter()

		// Setup CORS middleware
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:5173", "https://glen.dqx0.com"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300,
		}))

		// Setup WebAuthn routes
		if err := SetupWebAuthnRoutes(r, db, redisClient); err != nil {
			log.Fatal("Failed to setup WebAuthn routes:", err)
		}

		// Setup other routes
		// r.Route("/api/v1", func(r chi.Router) {
		//     // Your other API routes
		// })

		// Start server
		log.Println("Starting server on :8080")
		if err := http.ListenAndServe(":8080", r); err != nil {
			log.Fatal("Server failed:", err)
		}
	}
	*/
}

// WebAuthnHealthCheck provides a health check endpoint specifically for WebAuthn
func WebAuthnHealthCheck(db *sqlx.DB, redisClient *redis.Client) error {
	// Check database connectivity
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	// Check Redis connectivity
	ctx := context.Background()
	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}

	// Check WebAuthn tables
	migration := webauthn.NewDatabaseMigration(db)
	if err := migration.CheckWebAuthnTables(); err != nil {
		return fmt.Errorf("webauthn tables health check failed: %w", err)
	}

	return nil
}