package service

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
	"github.com/dqx0/glen/user-service/internal/webauthn/repository"
)

// Mock implementations for testing

type mockCredRepository struct {
	mock.Mock
}

func (m *mockCredRepository) CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *mockCredRepository) GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

func (m *mockCredRepository) GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	args := m.Called(ctx, credentialID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WebAuthnCredential), args.Error(1)
}

func (m *mockCredRepository) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *mockCredRepository) DeleteCredential(ctx context.Context, credentialID []byte) error {
	args := m.Called(ctx, credentialID)
	return args.Error(0)
}

func (m *mockCredRepository) GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, userID, transports)
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

func (m *mockCredRepository) UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	args := m.Called(ctx, credentialID, signCount)
	return args.Error(0)
}

func (m *mockCredRepository) UpdateCredentialLastUsed(ctx context.Context, credentialID []byte, lastUsed time.Time) error {
	args := m.Called(ctx, credentialID, lastUsed)
	return args.Error(0)
}

func (m *mockCredRepository) GetCredentialCount(ctx context.Context, userID string) (int, error) {
	args := m.Called(ctx, userID)
	return args.Int(0), args.Error(1)
}

func (m *mockCredRepository) GetCredentialsByTransport(ctx context.Context, transport models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, transport)
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

func (m *mockCredRepository) CleanupExpiredCredentials(ctx context.Context, retentionPeriod time.Duration) error {
	args := m.Called(ctx, retentionPeriod)
	return args.Error(0)
}

func (m *mockCredRepository) GetCredentialStatistics(ctx context.Context) (*repository.CredentialStatistics, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.CredentialStatistics), args.Error(1)
}

type mockSessionStore struct {
	mock.Mock
}

func (m *mockSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SessionData), args.Error(1)
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *mockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockSessionStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *mockSessionStore) GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*models.SessionData), args.Error(1)
}

func (m *mockSessionStore) ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error) {
	args := m.Called(ctx, sessionID, userID)
	return args.Bool(0), args.Error(1)
}

func (m *mockSessionStore) ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error {
	args := m.Called(ctx, sessionID, newExpiry)
	return args.Error(0)
}

type mockChallengeManager struct {
	mock.Mock
}

func (m *mockChallengeManager) GenerateChallenge(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockChallengeManager) ValidateChallenge(ctx context.Context, sessionID string, challenge []byte) error {
	args := m.Called(ctx, sessionID, challenge)
	return args.Error(0)
}

func (m *mockChallengeManager) CreateSession(ctx context.Context, session *models.SessionData) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *mockChallengeManager) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.SessionData), args.Error(1)
}

func (m *mockChallengeManager) InvalidateSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *mockChallengeManager) CleanupExpiredSessions(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Test helper functions

func createTestConfig() *WebAuthnConfig {
	return &WebAuthnConfig{
		RPID:                    "localhost",
		RPName:                  "Test Service",
		ChallengeLength:         32,
		ChallengeExpiry:         5 * time.Minute,
		SessionTimeout:          15 * time.Minute,
		MaxSessions:             5,
		AllowedOrigins:          []string{"http://localhost:3000"},
		CredentialTimeout:       60 * time.Second,
		MaxCredentialsPerUser:   10,
		RequireUserVerification: false,
		SignCountValidation:     true,
		CloneDetection:          true,
	}
}

func createTestCredential(userID string) *models.WebAuthnCredential {
	return &models.WebAuthnCredential{
		ID:           uuid.New().String(),
		UserID:       userID,
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
	}
}

func createTestSession(userID string) *models.SessionData {
	return &models.SessionData{
		ID:               uuid.New().String(),
		UserID:           userID,
		Challenge:        []byte("test-challenge-12345678901234567890"),
		ExpiresAt:        time.Now().Add(5 * time.Minute),
		CreatedAt:        time.Now(),
		UserVerification: models.UserVerificationRequired,
	}
}

// Tests

func TestNewWebAuthnService(t *testing.T) {
	tests := []struct {
		name        string
		webAuthn    *webauthn.WebAuthn
		credRepo    repository.WebAuthnRepository
		sessionStore repository.SessionStore
		challengeManager ChallengeManager
		config      *WebAuthnConfig
		expectError bool
	}{
		{
			name:        "Valid_Configuration",
			webAuthn:    &webauthn.WebAuthn{}, // Mock WebAuthn instance
			credRepo:    &mockCredRepository{},
			sessionStore: &mockSessionStore{},
			challengeManager: nil, // Will create default
			config:      createTestConfig(),
			expectError: false,
		},
		{
			name:        "Nil_Config",
			webAuthn:    &webauthn.WebAuthn{},
			credRepo:    &mockCredRepository{},
			sessionStore: &mockSessionStore{},
			challengeManager: nil,
			config:      nil,
			expectError: true,
		},
		{
			name:        "Nil_WebAuthn",
			webAuthn:    nil,
			credRepo:    &mockCredRepository{},
			sessionStore: &mockSessionStore{},
			challengeManager: nil,
			config:      createTestConfig(),
			expectError: true,
		},
		{
			name:        "Nil_CredRepo",
			webAuthn:    &webauthn.WebAuthn{},
			credRepo:    nil,
			sessionStore: &mockSessionStore{},
			challengeManager: nil,
			config:      createTestConfig(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewWebAuthnService(
				tt.webAuthn,
				tt.credRepo,
				tt.sessionStore,
				tt.challengeManager,
				tt.config,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, service)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestWebAuthnService_GetUserCredentials(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewWebAuthnService(
		&webauthn.WebAuthn{},
		mockRepo,
		mockStore,
		nil,
		config,
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := uuid.New().String()
	expectedCreds := []*models.WebAuthnCredential{
		createTestCredential(userID),
	}

	tests := []struct {
		name        string
		userID      string
		setupMocks  func()
		expectError bool
		expectedLen int
	}{
		{
			name:   "Valid_UserID_With_Credentials",
			userID: userID,
			setupMocks: func() {
				mockRepo.On("GetCredentialsByUserID", ctx, userID).Return(expectedCreds, nil)
			},
			expectError: false,
			expectedLen: 1,
		},
		{
			name:   "Valid_UserID_No_Credentials",
			userID: userID,
			setupMocks: func() {
				mockRepo.On("GetCredentialsByUserID", ctx, userID).Return([]*models.WebAuthnCredential{}, nil)
			},
			expectError: false,
			expectedLen: 0,
		},
		{
			name:        "Empty_UserID",
			userID:      "",
			setupMocks:  func() {},
			expectError: true,
			expectedLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			tt.setupMocks()

			credentials, err := service.GetUserCredentials(ctx, tt.userID)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, credentials)
			} else {
				require.NoError(t, err)
				assert.Len(t, credentials, tt.expectedLen)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestWebAuthnService_DeleteCredential(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewWebAuthnService(
		&webauthn.WebAuthn{},
		mockRepo,
		mockStore,
		nil,
		config,
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := uuid.New().String()
	credentialID := []byte("test-credential-id")
	credential := createTestCredential(userID)

	tests := []struct {
		name         string
		userID       string
		credentialID []byte
		setupMocks   func()
		expectError  bool
	}{
		{
			name:         "Valid_Deletion",
			userID:       userID,
			credentialID: credentialID,
			setupMocks: func() {
				mockRepo.On("GetCredentialByID", ctx, credentialID).Return(credential, nil)
				mockRepo.On("DeleteCredential", ctx, credentialID).Return(nil)
			},
			expectError: false,
		},
		{
			name:         "Empty_UserID",
			userID:       "",
			credentialID: credentialID,
			setupMocks:   func() {},
			expectError:  true,
		},
		{
			name:         "Empty_CredentialID", 
			userID:       userID,
			credentialID: []byte{},
			setupMocks:   func() {},
			expectError:  true,
		},
		{
			name:         "Credential_Not_Owned_By_User",
			userID:       "different-user-id",
			credentialID: credentialID,
			setupMocks: func() {
				mockRepo.On("GetCredentialByID", ctx, credentialID).Return(credential, nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			tt.setupMocks()

			err := service.DeleteCredential(ctx, tt.userID, tt.credentialID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestWebAuthnService_CleanupExpiredData(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	mockChallengeMgr := &mockChallengeManager{}
	config := createTestConfig()
	
	service, err := NewWebAuthnService(
		&webauthn.WebAuthn{},
		mockRepo,
		mockStore,
		mockChallengeMgr,
		config,
	)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name        string
		setupMocks  func()
		expectError bool
	}{
		{
			name: "Successful_Cleanup",
			setupMocks: func() {
				mockChallengeMgr.On("CleanupExpiredSessions", ctx).Return(nil)
				mockRepo.On("CleanupExpiredCredentials", ctx, mock.AnythingOfType("time.Duration")).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Session_Cleanup_Failure",
			setupMocks: func() {
				mockChallengeMgr.On("CleanupExpiredSessions", ctx).Return(assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			mockChallengeMgr.ExpectedCalls = nil
			tt.setupMocks()

			err := service.CleanupExpiredData(ctx)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockChallengeMgr.AssertExpectations(t)
		})
	}
}

func TestWebAuthnService_ValidateCredentialUsage(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewWebAuthnService(
		&webauthn.WebAuthn{},
		mockRepo,
		mockStore,
		nil,
		config,
	)
	require.NoError(t, err)

	ctx := context.Background()
	credentialID := []byte("test-credential-id")
	
	tests := []struct {
		name         string
		credentialID []byte
		signCount    uint32
		credential   *models.WebAuthnCredential
		setupMocks   func(*models.WebAuthnCredential)
		expectError  bool
	}{
		{
			name:         "Valid_Sign_Count_Increase",
			credentialID: credentialID,
			signCount:    5,
			credential: &models.WebAuthnCredential{
				CredentialID: credentialID,
				SignCount:    3,
				CloneWarning: false,
			},
			setupMocks: func(cred *models.WebAuthnCredential) {
				mockRepo.On("GetCredentialByID", ctx, credentialID).Return(cred, nil)
			},
			expectError: false,
		},
		{
			name:         "Sign_Count_Regression_Clone_Detection",
			credentialID: credentialID,
			signCount:    2,
			credential: &models.WebAuthnCredential{
				CredentialID: credentialID,
				SignCount:    5,
				CloneWarning: false,
			},
			setupMocks: func(cred *models.WebAuthnCredential) {
				mockRepo.On("GetCredentialByID", ctx, credentialID).Return(cred, nil)
				// Expect update to mark clone warning
				updatedCred := *cred
				updatedCred.CloneWarning = true
				mockRepo.On("UpdateCredential", ctx, &updatedCred).Return(nil)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			tt.setupMocks(tt.credential)

			err := service.ValidateCredentialUsage(ctx, tt.credentialID, tt.signCount)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}