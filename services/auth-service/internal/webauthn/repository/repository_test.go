package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Local test helpers
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// TestWebAuthnRepository_CreateCredential tests credential creation (TDD - RED)
func TestWebAuthnRepository_CreateCredential(t *testing.T) {
	tests := []struct {
		name         string
		credential   *models.WebAuthnCredential
		expectError  bool
		errorType    RepositoryErrorType
	}{
		{
			name: "Valid_Credential_Creation",
			credential: &models.WebAuthnCredential{
				ID:           uuid.New().String(),
				UserID:       uuid.New().String(),
				CredentialID: []byte("test-credential-id"),
				PublicKey:    []byte("test-public-key"),
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
			},
			expectError: false,
		},
		{
			name: "Duplicate_Credential_ID",
			credential: &models.WebAuthnCredential{
				ID:           uuid.New().String(),
				UserID:       uuid.New().String(),
				CredentialID: []byte("duplicate-credential-id"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
				SignCount:    0,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			expectError: true,
			errorType:   ErrRepositoryConflict,
		},
		{
			name: "Invalid_User_ID",
			credential: &models.WebAuthnCredential{
				ID:           uuid.New().String(),
				UserID:       "invalid-uuid",
				CredentialID: []byte("test-credential-id-2"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
				SignCount:    0,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			expectError: true,
			errorType:   ErrRepositoryConstraint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			env := NewTestEnvironment(t)
			defer env.CleanupTables(t)

			// Create repository using real implementation
			repo := NewPostgreSQLWebAuthnRepository(env.DB, &RepositoryConfig{
				QueryTimeout: 30 * time.Second,
			})

			// Execute test
			err := repo.CreateCredential(context.Background(), tt.credential)

			if tt.expectError {
				require.Error(t, err)
				assert.True(t, IsRepositoryError(err))
				
				repoErr := GetRepositoryError(err)
				require.NotNil(t, repoErr)
				assert.Equal(t, tt.errorType, repoErr.Type)
			} else {
				require.NoError(t, err)
				
				// Verify credential was created
				env.AssertCredentialExists(t, tt.credential.CredentialID)
			}
		})
	}
}

// TestWebAuthnRepository_GetCredentialsByUserID tests getting credentials by user ID
func TestWebAuthnRepository_GetCredentialsByUserID(t *testing.T) {
	tests := []struct {
		name              string
		userID            string
		setupCredentials  int
		expectedCount     int
		expectError       bool
	}{
		{
			name:              "User_With_Multiple_Credentials",
			userID:            uuid.New().String(),
			setupCredentials:  3,
			expectedCount:     3,
			expectError:       false,
		},
		{
			name:              "User_With_No_Credentials",
			userID:            uuid.New().String(),
			setupCredentials:  0,
			expectedCount:     0,
			expectError:       false,
		},
		{
			name:              "Invalid_User_ID",
			userID:            "invalid-uuid",
			setupCredentials:  0,
			expectedCount:     0,
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			env := NewTestEnvironment(t)
			defer env.CleanupTables(t)

			repo := NewPostgreSQLWebAuthnRepository(env.DB, &RepositoryConfig{
				QueryTimeout: 30 * time.Second,
			})

			// Setup test credentials if needed
			if tt.setupCredentials > 0 && tt.userID != "invalid-uuid" {
				for i := 0; i < tt.setupCredentials; i++ {
					credential := &models.WebAuthnCredential{
						ID:           uuid.New().String(),
						UserID:       tt.userID,
						CredentialID: []byte(uuid.New().String()),
						PublicKey:    []byte("test-public-key"),
						AttestationType: "none",
						SignCount:    0,
						CreatedAt:    time.Now(),
						UpdatedAt:    time.Now(),
					}
					err := repo.CreateCredential(context.Background(), credential)
					require.NoError(t, err)
				}
			}

			// Execute test
			credentials, err := repo.GetCredentialsByUserID(context.Background(), tt.userID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, credentials, tt.expectedCount)
				
				// Verify all credentials belong to the user
				for _, cred := range credentials {
					assert.Equal(t, tt.userID, cred.UserID)
				}
			}
		})
	}
}

// TestWebAuthnRepository_UpdateCredentialSignCount tests updating credential sign count
func TestWebAuthnRepository_UpdateCredentialSignCount(t *testing.T) {
	env := NewTestEnvironment(t)
	defer env.CleanupTables(t)

	repo := NewPostgreSQLWebAuthnRepository(env.DB, &RepositoryConfig{
		QueryTimeout: 30 * time.Second,
	})

	// Setup test credential
	credential := env.CreateTestCredential(t, uuid.New().String())
	
	tests := []struct {
		name         string
		credentialID []byte
		newSignCount uint32
		expectError  bool
	}{
		{
			name:         "Valid_Sign_Count_Update",
			credentialID: credential.CredentialID,
			newSignCount: 42,
			expectError:  false,
		},
		{
			name:         "Non_Existent_Credential",
			credentialID: []byte("non-existent"),
			newSignCount: 1,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.UpdateCredentialSignCount(context.Background(), tt.credentialID, tt.newSignCount)

			if tt.expectError {
				require.Error(t, err)
				assert.True(t, IsRepositoryError(err))
			} else {
				require.NoError(t, err)

				// Verify sign count was updated
				updatedCred, err := repo.GetCredentialByID(context.Background(), tt.credentialID)
				require.NoError(t, err)
				assert.Equal(t, tt.newSignCount, updatedCred.SignCount)
			}
		})
	}
}

// TestSessionStore_StoreSession tests session storage (TDD - RED)
func TestSessionStore_StoreSession(t *testing.T) {
	t.Skip("Skipping Redis tests until Redis connection is available")
	tests := []struct {
		name        string
		session     *models.SessionData
		expectError bool
		errorType   RepositoryErrorType
	}{
		{
			name: "Valid_Session_Storage",
			session: &models.SessionData{
				ID:               uuid.New().String(),
				UserID:           uuid.New().String(),
				Challenge:        []byte("test-challenge-data-12345678901234567890"),
				ExpiresAt:        time.Now().Add(5 * time.Minute),
				CreatedAt:        time.Now(),
				UserVerification: models.UserVerificationRequired,
			},
			expectError: false,
		},
		{
			name: "Duplicate_Session_ID",
			session: &models.SessionData{
				ID:               "duplicate-session-id",
				UserID:           uuid.New().String(),
				Challenge:        []byte("test-challenge-data-12345678901234567890"),
				ExpiresAt:        time.Now().Add(5 * time.Minute),
				CreatedAt:        time.Now(),
				UserVerification: models.UserVerificationRequired,
			},
			expectError: true,
			errorType:   ErrRepositoryConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test environment
			env := NewTestEnvironment(t)
			defer env.CleanupTables(t)

			// Create session store using real implementation  
			store := NewRedisSessionStore(env.RedisClient, &RepositoryConfig{
				QueryTimeout: 30 * time.Second,
			})

			// Execute test
			err := store.StoreSession(context.Background(), tt.session)

			if tt.expectError {
				require.Error(t, err)
				assert.True(t, IsRepositoryError(err))
				
				repoErr := GetRepositoryError(err)
				require.NotNil(t, repoErr)
				assert.Equal(t, tt.errorType, repoErr.Type)
			} else {
				require.NoError(t, err)
				
				// Verify session was stored
				env.AssertSessionExists(t, tt.session.ID)
			}
		})
	}
}

// TestSessionStore_GetSession tests session retrieval
func TestSessionStore_GetSession(t *testing.T) {
	t.Skip("Skipping Redis tests until Redis connection is available")
	env := NewTestEnvironment(t)
	defer env.CleanupTables(t)

	store := NewRedisSessionStore(env.RedisClient, &RepositoryConfig{
		QueryTimeout: 30 * time.Second,
	})

	// Setup test session
	testSession := env.CreateTestSession(t, uuid.New().String())

	tests := []struct {
		name        string
		sessionID   string
		expectError bool
		errorType   RepositoryErrorType
	}{
		{
			name:        "Valid_Session_Retrieval",
			sessionID:   testSession.ID,
			expectError: false,
		},
		{
			name:        "Non_Existent_Session",
			sessionID:   "non-existent-session",
			expectError: true,
			errorType:   ErrRepositoryNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, err := store.GetSession(context.Background(), tt.sessionID)

			if tt.expectError {
				require.Error(t, err)
				assert.True(t, IsRepositoryError(err))
				assert.Nil(t, session)
				
				repoErr := GetRepositoryError(err)
				require.NotNil(t, repoErr)
				assert.Equal(t, tt.errorType, repoErr.Type)
			} else {
				require.NoError(t, err)
				require.NotNil(t, session)
				assert.Equal(t, tt.sessionID, session.ID)
			}
		})
	}
}

// TestSessionStore_CleanupExpiredSessions tests expired session cleanup
func TestSessionStore_CleanupExpiredSessions(t *testing.T) {
	t.Skip("Skipping Redis tests until Redis connection is available")
	env := NewTestEnvironment(t)
	defer env.CleanupTables(t)

	store := NewRedisSessionStore(env.RedisClient, &RepositoryConfig{
		QueryTimeout: 30 * time.Second,
	})

	// Create expired session
	expiredSession := &models.SessionData{
		ID:               uuid.New().String(),
		UserID:           uuid.New().String(),
		Challenge:        []byte("expired-challenge-data-12345678901234567890"),
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:        time.Now().Add(-2 * time.Hour),
		UserVerification: models.UserVerificationRequired,
	}

	// Create valid session
	validSession := &models.SessionData{
		ID:               uuid.New().String(),
		UserID:           uuid.New().String(),
		Challenge:        []byte("valid-challenge-data-12345678901234567890"),
		ExpiresAt:        time.Now().Add(1 * time.Hour), // Valid
		CreatedAt:        time.Now(),
		UserVerification: models.UserVerificationRequired,
	}

	// Store both sessions
	err := store.StoreSession(context.Background(), expiredSession)
	require.NoError(t, err)
	err = store.StoreSession(context.Background(), validSession)
	require.NoError(t, err)

	// Execute cleanup
	err = store.CleanupExpiredSessions(context.Background())
	require.NoError(t, err)

	// Verify expired session is removed
	_, err = store.GetSession(context.Background(), expiredSession.ID)
	require.Error(t, err)
	assert.True(t, IsRepositoryError(err))

	// Verify valid session still exists
	retrievedSession, err := store.GetSession(context.Background(), validSession.ID)
	require.NoError(t, err)
	assert.Equal(t, validSession.ID, retrievedSession.ID)
}

// Mock implementations for testing (will be replaced with real implementations)

// NewPostgreSQLWebAuthnRepository and NewRedisSessionStore are now implemented in separate files
// These are kept for backward compatibility during testing

// Mock implementations for testing
type mockWebAuthnRepository struct{}

func (m *mockWebAuthnRepository) CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	// Mock implementation for testing
	if string(credential.CredentialID) == "duplicate-credential-id" {
		return NewRepositoryError(ErrRepositoryConflict, "Credential ID already exists", nil)
	}
	if credential.UserID == "invalid-uuid" {
		return NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", nil)
	}
	return nil
}

func (m *mockWebAuthnRepository) GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	if userID == "invalid-uuid" {
		return nil, NewRepositoryError(ErrRepositoryConstraint, "Invalid user ID format", nil)
	}
	return []*models.WebAuthnCredential{}, nil
}

func (m *mockWebAuthnRepository) GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	return &models.WebAuthnCredential{
		CredentialID: credentialID,
		SignCount:    42,
	}, nil
}

func (m *mockWebAuthnRepository) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	return nil
}

func (m *mockWebAuthnRepository) DeleteCredential(ctx context.Context, credentialID []byte) error {
	return nil
}

func (m *mockWebAuthnRepository) GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	return []*models.WebAuthnCredential{}, nil
}

func (m *mockWebAuthnRepository) UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	if string(credentialID) == "non-existent" {
		return NewRepositoryError(ErrRepositoryNotFound, "Credential not found", nil)
	}
	return nil
}

func (m *mockWebAuthnRepository) UpdateCredentialLastUsed(ctx context.Context, credentialID []byte, lastUsed time.Time) error {
	return nil
}

func (m *mockWebAuthnRepository) GetCredentialCount(ctx context.Context, userID string) (int, error) {
	return 0, nil
}

func (m *mockWebAuthnRepository) GetCredentialsByTransport(ctx context.Context, transport models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	return []*models.WebAuthnCredential{}, nil
}

func (m *mockWebAuthnRepository) CleanupExpiredCredentials(ctx context.Context, retentionPeriod time.Duration) error {
	return nil
}

func (m *mockWebAuthnRepository) GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error) {
	return &CredentialStatistics{}, nil
}

type mockSessionStore struct{}

func (m *mockSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	if session.ID == "duplicate-session-id" {
		return NewRepositoryError(ErrRepositoryConflict, "Session ID already exists", nil)
	}
	return nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	if sessionID == "non-existent-session" {
		return nil, NewRepositoryError(ErrRepositoryNotFound, "Session not found", nil)
	}
	return &models.SessionData{ID: sessionID}, nil
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	return nil
}

func (m *mockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	return nil
}

func (m *mockSessionStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	return 0, nil
}

func (m *mockSessionStore) GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error) {
	return []*models.SessionData{}, nil
}

func (m *mockSessionStore) ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error) {
	return true, nil
}

func (m *mockSessionStore) ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error {
	return nil
}