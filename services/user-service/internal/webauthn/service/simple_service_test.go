package service

import (
	"context"
	"testing"
	"time"

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

func TestNewSimpleWebAuthnService(t *testing.T) {
	tests := []struct {
		name         string
		credRepo     *mockCredRepository
		sessionStore *mockSessionStore
		config       *WebAuthnConfig
		expectError  bool
	}{
		{
			name:         "Valid_Configuration",
			credRepo:     &mockCredRepository{},
			sessionStore: &mockSessionStore{},
			config:       createTestConfig(),
			expectError:  false,
		},
		{
			name:         "Nil_Config",
			credRepo:     &mockCredRepository{},
			sessionStore: &mockSessionStore{},
			config:       nil,
			expectError:  true,
		},
		{
			name:         "Nil_CredRepo",
			credRepo:     nil,
			sessionStore: &mockSessionStore{},
			config:       createTestConfig(),
			expectError:  true,
		},
		{
			name:         "Nil_SessionStore",
			credRepo:     &mockCredRepository{},
			sessionStore: nil,
			config:       createTestConfig(),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewSimpleWebAuthnService(
				tt.credRepo,
				tt.sessionStore,
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

func TestSimpleWebAuthnService_GetUserCredentials(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewSimpleWebAuthnService(mockRepo, mockStore, config)
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

func TestSimpleWebAuthnService_BeginRegistration(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewSimpleWebAuthnService(mockRepo, mockStore, config)
	require.NoError(t, err)

	ctx := context.Background()
	userID := uuid.New().String()

	tests := []struct {
		name        string
		request     *RegistrationStartRequest
		setupMocks  func()
		expectError bool
	}{
		{
			name: "Valid_Registration_Start",
			request: &RegistrationStartRequest{
				UserID:      userID,
				Username:    "testuser",
				DisplayName: "Test User",
			},
			setupMocks: func() {
				mockRepo.On("GetCredentialCount", ctx, userID).Return(0, nil)
				mockStore.On("StoreSession", ctx, matchSessionData()).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Credential_Limit_Exceeded",
			request: &RegistrationStartRequest{
				UserID:   userID,
				Username: "testuser",
			},
			setupMocks: func() {
				mockRepo.On("GetCredentialCount", ctx, userID).Return(config.MaxCredentialsPerUser, nil)
			},
			expectError: true,
		},
		{
			name:        "Invalid_Request",
			request:     &RegistrationStartRequest{},
			setupMocks:  func() {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			mockStore.ExpectedCalls = nil
			tt.setupMocks()

			response, err := service.BeginRegistration(ctx, tt.request)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.SessionID)
				assert.NotNil(t, response.CreationOptions)
				assert.NotEmpty(t, response.CreationOptions.Challenge)
			}

			mockRepo.AssertExpectations(t)
			mockStore.AssertExpectations(t)
		})
	}
}

func TestSimpleWebAuthnService_FinishRegistration(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewSimpleWebAuthnService(mockRepo, mockStore, config)
	require.NoError(t, err)

	ctx := context.Background()
	userID := uuid.New().String()
	sessionID := uuid.New().String()
	session := createTestSession(userID)
	session.ID = sessionID

	tests := []struct {
		name        string
		request     *RegistrationFinishRequest
		setupMocks  func()
		expectError bool
	}{
		{
			name: "Valid_Registration_Finish",
			request: &RegistrationFinishRequest{
				SessionID: sessionID,
				AttestationResponse: &models.AuthenticatorAttestationResponse{
					ID:   "test-credential",
					Type: "public-key",
				},
			},
			setupMocks: func() {
				mockStore.On("GetSession", ctx, sessionID).Return(session, nil)
				mockRepo.On("CreateCredential", ctx, matchCredential()).Return(nil)
				mockStore.On("DeleteSession", ctx, sessionID).Return(nil)
			},
			expectError: false,
		},
		{
			name: "Session_Not_Found",
			request: &RegistrationFinishRequest{
				SessionID: sessionID,
				AttestationResponse: &models.AuthenticatorAttestationResponse{
					ID:   "test-credential",
					Type: "public-key",
				},
			},
			setupMocks: func() {
				mockStore.On("GetSession", ctx, sessionID).Return(nil, assert.AnError)
			},
			expectError: false, // Returns result with error, not error directly
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			mockStore.ExpectedCalls = nil
			tt.setupMocks()

			result, err := service.FinishRegistration(ctx, tt.request)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, result)
			}

			mockRepo.AssertExpectations(t)
			mockStore.AssertExpectations(t)
		})
	}
}

func TestSimpleWebAuthnService_BeginAuthentication(t *testing.T) {
	mockRepo := &mockCredRepository{}
	mockStore := &mockSessionStore{}
	config := createTestConfig()
	
	service, err := NewSimpleWebAuthnService(mockRepo, mockStore, config)
	require.NoError(t, err)

	ctx := context.Background()
	userID := uuid.New().String()
	credentials := []*models.WebAuthnCredential{
		createTestCredential(userID),
	}

	tests := []struct {
		name        string
		request     *AuthenticationStartRequest
		setupMocks  func()
		expectError bool
	}{
		{
			name: "Valid_Authentication_Start",
			request: &AuthenticationStartRequest{
				UserID: userID,
			},
			setupMocks: func() {
				mockRepo.On("GetCredentialsByUserID", ctx, userID).Return(credentials, nil)
				mockStore.On("StoreSession", ctx, matchSessionData()).Return(nil)
			},
			expectError: false,
		},
		{
			name: "No_Credentials_Found",
			request: &AuthenticationStartRequest{
				UserID: userID,
			},
			setupMocks: func() {
				mockRepo.On("GetCredentialsByUserID", ctx, userID).Return([]*models.WebAuthnCredential{}, nil)
			},
			expectError: true,
		},
		{
			name:        "Invalid_Request",
			request:     &AuthenticationStartRequest{},
			setupMocks:  func() {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockRepo.ExpectedCalls = nil
			mockStore.ExpectedCalls = nil
			tt.setupMocks()

			response, err := service.BeginAuthentication(ctx, tt.request)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.SessionID)
				assert.NotNil(t, response.RequestOptions)
				assert.NotEmpty(t, response.RequestOptions.Challenge)
			}

			mockRepo.AssertExpectations(t)
			mockStore.AssertExpectations(t)
		})
	}
}

// Helper functions for mock matching

func matchSessionData() interface{} {
	return mock.MatchedBy(func(session *models.SessionData) bool {
		return session != nil && 
			   session.ID != "" && 
			   session.UserID != "" && 
			   len(session.Challenge) > 0 &&
			   !session.ExpiresAt.IsZero()
	})
}

func matchCredential() interface{} {
	return mock.MatchedBy(func(cred *models.WebAuthnCredential) bool {
		return cred != nil && 
			   cred.ID != "" && 
			   cred.UserID != "" && 
			   len(cred.CredentialID) > 0 &&
			   len(cred.PublicKey) > 0
	})
}