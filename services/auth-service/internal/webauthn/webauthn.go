package webauthn

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"

	"github.com/dqx0/glen/auth-service/internal/webauthn/config"
	"github.com/dqx0/glen/auth-service/internal/webauthn/handlers"
	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/repository"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// WebAuthnModule represents the complete WebAuthn module
type WebAuthnModule struct {
	Service service.WebAuthnService
	Handler *handlers.WebAuthnHandler
	Config  *config.WebAuthnConfig
}

// NewWebAuthnModule creates a new WebAuthn module with all dependencies
func NewWebAuthnModule(db *sqlx.DB, redisClient *redis.Client, cfg *config.WebAuthnConfig) (*WebAuthnModule, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	
	if redisClient == nil {
		return nil, fmt.Errorf("redis connection is required")
	}
	
	if cfg == nil {
		return nil, fmt.Errorf("WebAuthn configuration is required")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid WebAuthn configuration: %w", err)
	}

	// Initialize repository layer
	repoConfig := &repository.RepositoryConfig{
		MaxOpenConns:              25,
		MaxIdleConns:              5,
		ConnMaxLifetime:           1 * time.Hour,
		QueryTimeout:              30 * time.Second,
		SessionCleanupInterval:    1 * time.Hour,
		MaxSessionsPerUser:        5,
		CredentialRetentionPeriod: 2160 * time.Hour, // 90 days
	}

	credRepo := repository.NewPostgreSQLWebAuthnRepository(db, repoConfig)
	sessionStore := repository.NewRedisSessionStore(redisClient, repoConfig)

	// Initialize service layer with database user service
	databaseUserService := service.NewDatabaseUserService(db.DB)
	fmt.Printf("[INIT] Using DatabaseUserService for user lookups\n")
	webAuthnService, err := service.NewWebAuthnServiceWithUserService(credRepo, sessionStore, cfg, databaseUserService)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn service: %w", err)
	}

	// Initialize handler layer (we'll create a dummy JWT config for now)
	// The actual JWT integration will be done in main.go
	dummyJWTConfig := &middleware.JWTConfig{}
	webAuthnHandler := handlers.NewWebAuthnHandler(webAuthnService, dummyJWTConfig)

	return &WebAuthnModule{
		Service: webAuthnService,
		Handler: webAuthnHandler,
		Config:  cfg,
	}, nil
}

// HealthCheck performs a health check on the WebAuthn module
func (m *WebAuthnModule) HealthCheck() error {
	// This could include checks like:
	// - Database connectivity
	// - Redis connectivity
	// - Service availability
	// - Configuration validation
	
	if m.Service == nil {
		return fmt.Errorf("WebAuthn service is not initialized")
	}
	
	if m.Handler == nil {
		return fmt.Errorf("WebAuthn handler is not initialized")
	}
	
	if m.Config == nil {
		return fmt.Errorf("WebAuthn configuration is not loaded")
	}

	return nil
}

// DatabaseMigration contains database migration utilities
type DatabaseMigration struct {
	db *sqlx.DB
}

// NewDatabaseMigration creates a new database migration helper
func NewDatabaseMigration(db *sqlx.DB) *DatabaseMigration {
	return &DatabaseMigration{db: db}
}

// CheckWebAuthnTables checks if WebAuthn tables exist
func (m *DatabaseMigration) CheckWebAuthnTables() error {
	// Check webauthn_credentials table
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'webauthn_credentials'
		)`
	
	if err := m.db.QueryRow(query).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check webauthn_credentials table: %w", err)
	}
	
	if !exists {
		return fmt.Errorf("webauthn_credentials table does not exist")
	}

	// Check webauthn_sessions table
	query = `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = 'webauthn_sessions'
		)`
	
	if err := m.db.QueryRow(query).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check webauthn_sessions table: %w", err)
	}
	
	if !exists {
		return fmt.Errorf("webauthn_sessions table does not exist")
	}

	return nil
}

// CreateWebAuthnTables creates WebAuthn tables if they don't exist
func (m *DatabaseMigration) CreateWebAuthnTables() error {
	// Create webauthn_credentials table
	credentialsTableSQL := `
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL,
			credential_id BYTEA NOT NULL UNIQUE,
			public_key BYTEA NOT NULL,
			attestation_type VARCHAR(50) DEFAULT 'none',
			transport TEXT,
			flags JSONB DEFAULT '{}',
			sign_count INTEGER DEFAULT 0,
			clone_warning BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			last_used_at TIMESTAMP WITH TIME ZONE
		);
		
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_created_at ON webauthn_credentials(created_at);
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_last_used_at ON webauthn_credentials(last_used_at);
	`

	if _, err := m.db.Exec(credentialsTableSQL); err != nil {
		return fmt.Errorf("failed to create webauthn_credentials table: %w", err)
	}

	// Create webauthn_sessions table
	sessionsTableSQL := `
		CREATE TABLE IF NOT EXISTS webauthn_sessions (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL,
			challenge BYTEA NOT NULL,
			allowed_credential_ids JSONB,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			user_verification VARCHAR(20) DEFAULT 'preferred'
		);
		
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_created_at ON webauthn_sessions(created_at);
	`

	if _, err := m.db.Exec(sessionsTableSQL); err != nil {
		return fmt.Errorf("failed to create webauthn_sessions table: %w", err)
	}

	return nil
}

// DropWebAuthnTables drops WebAuthn tables (use with caution)
func (m *DatabaseMigration) DropWebAuthnTables() error {
	dropSQL := `
		DROP TABLE IF EXISTS webauthn_sessions;
		DROP TABLE IF EXISTS webauthn_credentials;
	`

	if _, err := m.db.Exec(dropSQL); err != nil {
		return fmt.Errorf("failed to drop WebAuthn tables: %w", err)
	}

	return nil
}

// WebAuthnConfig represents runtime configuration
type WebAuthnRuntimeConfig struct {
	// Database settings
	DatabaseURL string `env:"DATABASE_URL"`
	
	// Redis settings
	RedisURL string `env:"REDIS_URL"`
	
	// WebAuthn settings (will be loaded from config package)
	WebAuthnConfigFile string `env:"WEBAUTHN_CONFIG_FILE"`
	
	// Security settings
	JWTSecret          string `env:"JWT_SECRET"`
	AllowedOrigins     string `env:"ALLOWED_ORIGINS"`
	RequireHTTPS       bool   `env:"REQUIRE_HTTPS" default:"true"`
	
	// Rate limiting
	EnableRateLimit    bool `env:"ENABLE_RATE_LIMIT" default:"true"`
	RateLimitPerMinute int  `env:"RATE_LIMIT_PER_MINUTE" default:"60"`
	
	// Monitoring
	EnableMetrics bool `env:"ENABLE_METRICS" default:"true"`
	MetricsPort   int  `env:"METRICS_PORT" default:"9090"`
}

// LoadRuntimeConfig loads runtime configuration from environment
func LoadRuntimeConfig() *WebAuthnRuntimeConfig {
	return &WebAuthnRuntimeConfig{
		DatabaseURL:        getEnvOrDefault("DATABASE_URL", ""),
		RedisURL:           getEnvOrDefault("REDIS_URL", "redis://localhost:6379"),
		WebAuthnConfigFile: getEnvOrDefault("WEBAUTHN_CONFIG_FILE", ""),
		JWTSecret:          getEnvOrDefault("JWT_SECRET", "default-secret-change-in-production"),
		AllowedOrigins:     getEnvOrDefault("ALLOWED_ORIGINS", "http://localhost:3000,https://glen.dqx0.com"),
		RequireHTTPS:       getEnvBoolOrDefault("REQUIRE_HTTPS", true),
		EnableRateLimit:    getEnvBoolOrDefault("ENABLE_RATE_LIMIT", true),
		RateLimitPerMinute: getEnvIntOrDefault("RATE_LIMIT_PER_MINUTE", 60),
		EnableMetrics:      getEnvBoolOrDefault("ENABLE_METRICS", true),
		MetricsPort:        getEnvIntOrDefault("METRICS_PORT", 9090),
	}
}

// Helper functions for environment variable parsing
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// NewWebAuthnHandlerWithJWT creates a new WebAuthn handler with proper JWT configuration
func NewWebAuthnHandlerWithJWT(webAuthnService service.WebAuthnService, jwtConfig *middleware.JWTConfig) *handlers.WebAuthnHandler {
	return handlers.NewWebAuthnHandler(webAuthnService, jwtConfig)
}