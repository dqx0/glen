package testutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/google/uuid"

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
)

// WebAuthnTestEnvironment provides a test environment with database and Redis connections for WebAuthn testing
type WebAuthnTestEnvironment struct {
	DB          *sqlx.DB
	RedisClient *redis.Client
	t           *testing.T
}

// NewWebAuthnTestEnvironment creates a new test environment for WebAuthn testing
func NewWebAuthnTestEnvironment(t *testing.T) *WebAuthnTestEnvironment {
	// For testing, we'll use in-memory or test databases
	// In a real implementation, you might use Docker containers or test databases
	
	// Initialize test database (SQLite for simplicity in testing)
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Initialize test Redis (you might use miniredis for testing)
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // This would be configured for test environment
		DB:   1, // Use a different DB for testing
	})

	env := &WebAuthnTestEnvironment{
		DB:          db,
		RedisClient: redisClient,
		t:           t,
	}

	// Setup test schema
	env.setupTestSchema()

	return env
}

// setupTestSchema creates the necessary tables for testing
func (env *WebAuthnTestEnvironment) setupTestSchema() {
	// Create webauthn_credentials table
	createCredentialsTable := `
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id BLOB UNIQUE NOT NULL,
		public_key BLOB NOT NULL,
		attestation_type TEXT,
		transport TEXT,
		flags TEXT,
		sign_count INTEGER DEFAULT 0,
		clone_warning BOOLEAN DEFAULT FALSE,
		created_at DATETIME,
		updated_at DATETIME,
		last_used_at DATETIME
	)`

	_, err := env.DB.Exec(createCredentialsTable)
	if err != nil {
		env.t.Fatalf("Failed to create test credentials table: %v", err)
	}
}

// CleanupTables cleans up test data
func (env *WebAuthnTestEnvironment) CleanupTables(t *testing.T) {
	// Clean up database
	_, err := env.DB.Exec("DELETE FROM webauthn_credentials")
	if err != nil {
		t.Logf("Failed to cleanup credentials table: %v", err)
	}

	// Clean up Redis
	err = env.RedisClient.FlushDB(env.RedisClient.Context()).Err()
	if err != nil {
		t.Logf("Failed to cleanup Redis: %v", err)
	}

	// Close connections
	if env.DB != nil {
		env.DB.Close()
	}
	if env.RedisClient != nil {
		env.RedisClient.Close()
	}
}

// AssertCredentialExists verifies that a credential exists in the database
func (env *WebAuthnTestEnvironment) AssertCredentialExists(t *testing.T, credentialID []byte) {
	var count int
	err := env.DB.QueryRow("SELECT COUNT(*) FROM webauthn_credentials WHERE credential_id = ?", credentialID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "Credential should exist in database")
}

// AssertSessionExists verifies that a session exists in Redis
func (env *WebAuthnTestEnvironment) AssertSessionExists(t *testing.T, sessionID string) {
	exists, err := env.RedisClient.Exists(env.RedisClient.Context(), "webauthn:session:"+sessionID).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), exists, "Session should exist in Redis")
}

// CreateTestCredential creates a test credential
func (env *WebAuthnTestEnvironment) CreateTestCredential(t *testing.T, userID string) *models.WebAuthnCredential {
	credential := &models.WebAuthnCredential{
		ID:           uuid.New().String(),
		UserID:       userID,
		CredentialID: []byte(uuid.New().String()),
		PublicKey:    []byte("test-public-key-data"),
		AttestationType: "none",
		Transport: []models.AuthenticatorTransport{
			models.TransportUSB,
		},
		Flags: models.AuthenticatorFlags{
			UserPresent: true,
		},
		SignCount: 0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Insert directly into database for setup
	query := `
		INSERT INTO webauthn_credentials (
			id, user_id, credential_id, public_key, attestation_type,
			transport, flags, sign_count, clone_warning, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := env.DB.Exec(query,
		credential.ID,
		credential.UserID,
		credential.CredentialID,
		credential.PublicKey,
		credential.AttestationType,
		models.TransportsToString(credential.Transport),
		"{}",  // Simplified flags for SQLite
		credential.SignCount,
		credential.CloneWarning,
		credential.CreatedAt,
		credential.UpdatedAt,
	)

	require.NoError(t, err)
	return credential
}

// CreateTestSession creates a test session
func (env *WebAuthnTestEnvironment) CreateTestSession(t *testing.T, userID string) *models.SessionData {
	session := &models.SessionData{
		ID:               uuid.New().String(),
		UserID:           userID,
		Challenge:        []byte("test-challenge-data-12345678901234567890"),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
		CreatedAt:        time.Now(),
		UserVerification: models.UserVerificationRequired,
	}

	// Store directly in Redis for setup
	err := env.RedisClient.Set(env.RedisClient.Context(), 
		"webauthn:session:"+session.ID, 
		fmt.Sprintf(`{"id":"%s","user_id":"%s","challenge":"%s","expires_at":"%s","created_at":"%s","user_verification":"%s"}`,
			session.ID, session.UserID, string(session.Challenge), 
			session.ExpiresAt.Format(time.RFC3339), 
			session.CreatedAt.Format(time.RFC3339),
			session.UserVerification),
		time.Until(session.ExpiresAt)).Err()

	require.NoError(t, err)
	return session
}

// DatabaseConfig provides test database configuration
type DatabaseConfig struct {
	Driver   string
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string
}

// GetTestDatabaseConfig returns configuration for test database
func GetTestDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Driver:   "sqlite3",
		Host:     "",
		Port:     0,
		Name:     ":memory:",
		User:     "",
		Password: "",
		SSLMode:  "",
	}
}

// RedisConfig provides test Redis configuration
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// GetTestRedisConfig returns configuration for test Redis
func GetTestRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       1, // Use test database
	}
}