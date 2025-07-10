package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	_ "github.com/mattn/go-sqlite3" // SQLite driver

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
)

// TestEnvironment provides a complete test environment with database and Redis
type TestEnvironment struct {
	PostgresContainer testcontainers.Container
	RedisContainer    testcontainers.Container
	DB               *sql.DB
	RedisClient      interface{} // Will be replaced with actual Redis client
	Context          context.Context
	cleanup          func()
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	ctx := context.Background()

	// Start PostgreSQL container
	postgresContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("glen_test"),
		postgres.WithUsername("glen_test"),
		postgres.WithPassword("glen_test"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections")),
	)
	require.NoError(t, err)

	// Start Redis container
	redisContainer, err := redis.RunContainer(ctx,
		testcontainers.WithImage("redis:7-alpine"),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections")),
	)
	require.NoError(t, err)

	// Get database connection
	dbURL, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", dbURL)
	require.NoError(t, err)

	// Run migrations
	err = runMigrations(db)
	require.NoError(t, err)

	cleanup := func() {
		if db != nil {
			db.Close()
		}
		if postgresContainer != nil {
			postgresContainer.Terminate(ctx)
		}
		if redisContainer != nil {
			redisContainer.Terminate(ctx)
		}
	}

	// Register cleanup
	t.Cleanup(cleanup)

	return &TestEnvironment{
		PostgresContainer: postgresContainer,
		RedisContainer:    redisContainer,
		DB:               db,
		Context:          ctx,
		cleanup:          cleanup,
	}
}

// runMigrations runs database migrations for testing
func runMigrations(db *sql.DB) error {
	// Create webauthn_credentials table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			credential_id BYTEA NOT NULL UNIQUE,
			public_key BYTEA NOT NULL,
			attestation_type VARCHAR(50) NOT NULL DEFAULT 'none',
			transport TEXT[] DEFAULT '{}',
			flags JSONB NOT NULL DEFAULT '{}',
			sign_count BIGINT NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			last_used_at TIMESTAMP WITH TIME ZONE,
			CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create webauthn_credentials table: %w", err)
	}

	// Create webauthn_sessions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS webauthn_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			challenge BYTEA NOT NULL,
			allowed_credential_ids BYTEA[],
			user_verification VARCHAR(20) NOT NULL DEFAULT 'preferred',
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create webauthn_sessions table: %w", err)
	}

	// Create indices
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_challenge ON webauthn_sessions(challenge);
		CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at);
	`)
	if err != nil {
		return fmt.Errorf("failed to create indices: %w", err)
	}

	return nil
}

// CreateTestCredential creates a test WebAuthn credential
func (te *TestEnvironment) CreateTestCredential(t *testing.T, userID string) *models.WebAuthnCredential {
	credential := &models.WebAuthnCredential{
		ID:           uuid.New().String(),
		UserID:       userID,
		CredentialID: []byte("test-credential-id-" + uuid.New().String()),
		PublicKey:    []byte("test-public-key-data"),
		AttestationType: "none",
		Transport: []models.AuthenticatorTransport{
			models.TransportUSB,
			models.TransportInternal,
		},
		Flags: models.AuthenticatorFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: false,
			BackupState:    false,
		},
		SignCount:    0,
		CloneWarning: false,
		CreatedAt:    time.Now(),
	}

	// Insert into database
	_, err := te.DB.Exec(`
		INSERT INTO webauthn_credentials (
			id, user_id, credential_id, public_key, attestation_type,
			transport, flags, sign_count, clone_warning, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		credential.ID,
		credential.UserID,
		credential.CredentialID,
		credential.PublicKey,
		credential.AttestationType,
		// Convert transport to string array for PostgreSQL
		fmt.Sprintf("{%s}", string(credential.Transport[0])+","+string(credential.Transport[1])),
		// Convert flags to JSON
		`{"user_present": true, "user_verified": true, "backup_eligible": false, "backup_state": false}`,
		credential.SignCount,
		credential.CloneWarning,
		credential.CreatedAt,
	)
	require.NoError(t, err)

	return credential
}

// CreateTestSession creates a test WebAuthn session
func (te *TestEnvironment) CreateTestSession(t *testing.T, userID string) *models.SessionData {
	session := &models.SessionData{
		ID:                    uuid.New().String(),
		UserID:                userID,
		Challenge:             []byte("test-challenge-" + uuid.New().String()),
		AllowedCredentialIDs:  [][]byte{[]byte("test-credential-1"), []byte("test-credential-2")},
		UserVerification:      models.UserVerificationPreferred,
		ExpiresAt:             time.Now().Add(5 * time.Minute),
		CreatedAt:             time.Now(),
	}

	// Insert into database
	_, err := te.DB.Exec(`
		INSERT INTO webauthn_sessions (
			id, user_id, challenge, allowed_credential_ids,
			user_verification, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`,
		session.ID,
		session.UserID,
		session.Challenge,
		// Convert to PostgreSQL bytea array format
		`{"\\x746573742d63726564656e7469616c2d31", "\\x746573742d63726564656e7469616c2d32"}`,
		string(session.UserVerification),
		session.ExpiresAt,
		session.CreatedAt,
	)
	require.NoError(t, err)

	return session
}

// CleanupTables cleans up test data from tables
func (te *TestEnvironment) CleanupTables(t *testing.T) {
	_, err := te.DB.Exec("DELETE FROM webauthn_sessions")
	require.NoError(t, err)

	_, err = te.DB.Exec("DELETE FROM webauthn_credentials")
	require.NoError(t, err)
}

// AssertCredentialExists verifies that a credential exists in the database
func (te *TestEnvironment) AssertCredentialExists(t *testing.T, credentialID []byte) {
	var exists bool
	err := te.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id = $1)", credentialID).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "Credential should exist in database")
}

// AssertSessionExists verifies that a session exists in the database
func (te *TestEnvironment) AssertSessionExists(t *testing.T, sessionID string) {
	var exists bool
	err := te.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM webauthn_sessions WHERE id = $1)", sessionID).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "Session should exist in database")
}

// GetTestContext returns a context with request ID for testing
func GetTestContext() context.Context {
	ctx := context.Background()
	return context.WithValue(ctx, "request_id", uuid.New().String())
}

// GenerateTestChallenge generates a test challenge for WebAuthn
func GenerateTestChallenge() []byte {
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i % 256)
	}
	return challenge
}

// GenerateTestUserID generates a test user ID
func GenerateTestUserID() string {
	return uuid.New().String()
}