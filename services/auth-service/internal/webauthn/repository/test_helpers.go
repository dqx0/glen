package repository

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"github.com/google/uuid"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// TestEnvironment provides a test environment with database and Redis connections
type TestEnvironment struct {
	DB          *sqlx.DB
	RedisClient *redis.Client
	t           *testing.T
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	// Initialize test database (SQLite for simplicity in testing)
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Initialize mock Redis client for testing (avoid actual Redis connection)
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})
	// Note: In actual tests, we might use a mock or in-memory Redis implementation

	env := &TestEnvironment{
		DB:          db,
		RedisClient: redisClient,
		t:           t,
	}

	// Setup test schema
	env.setupTestSchema()

	return env
}

// setupTestSchema creates the necessary tables for testing
func (env *TestEnvironment) setupTestSchema() {
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
		last_used_at DATETIME,
		name TEXT NOT NULL DEFAULT 'Security Key'
	)`

	_, err := env.DB.Exec(createCredentialsTable)
	if err != nil {
		env.t.Fatalf("Failed to create test credentials table: %v", err)
	}
}

// CleanupTables cleans up test data
func (env *TestEnvironment) CleanupTables(t *testing.T) {
	// Clean up database
	_, err := env.DB.Exec("DELETE FROM webauthn_credentials")
	if err != nil {
		t.Logf("Failed to cleanup credentials table: %v", err)
	}

	// Clean up Redis (skip if no connection)
	if env.RedisClient != nil {
		err = env.RedisClient.FlushDB(env.RedisClient.Context()).Err()
		if err != nil {
			t.Logf("Failed to cleanup Redis: %v", err)
		}
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
func (env *TestEnvironment) AssertCredentialExists(t *testing.T, credentialID []byte) {
	var count int
	err := env.DB.QueryRow("SELECT COUNT(*) FROM webauthn_credentials WHERE credential_id = ?", credentialID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "Credential should exist in database")
}

// AssertSessionExists verifies that a session exists in Redis
func (env *TestEnvironment) AssertSessionExists(t *testing.T, sessionID string) {
	exists, err := env.RedisClient.Exists(env.RedisClient.Context(), "webauthn:session:"+sessionID).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), exists, "Session should exist in Redis")
}

// CreateTestCredential creates a test credential
func (env *TestEnvironment) CreateTestCredential(t *testing.T, userID string) *models.WebAuthnCredential {
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
			transport, flags, sign_count, clone_warning, created_at, updated_at, name
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
		"Test Security Key", // Default name for test credentials
	)

	require.NoError(t, err)
	return credential
}

// CreateTestSession creates a test session
func (env *TestEnvironment) CreateTestSession(t *testing.T, userID string) *models.SessionData {
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