package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/user-service/internal/webauthn/models"
	"github.com/dqx0/glen/user-service/internal/webauthn/service"
)

// Mock WebAuthn service for testing
type mockWebAuthnService struct {
	mock.Mock
}

func (m *mockWebAuthnService) BeginRegistration(ctx context.Context, req *service.RegistrationStartRequest) (*service.RegistrationStartResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.RegistrationStartResponse), args.Error(1)
}

func (m *mockWebAuthnService) FinishRegistration(ctx context.Context, req *service.RegistrationFinishRequest) (*service.RegistrationResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.RegistrationResult), args.Error(1)
}

func (m *mockWebAuthnService) BeginAuthentication(ctx context.Context, req *service.AuthenticationStartRequest) (*service.AuthenticationStartResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthenticationStartResponse), args.Error(1)
}

func (m *mockWebAuthnService) FinishAuthentication(ctx context.Context, req *service.AuthenticationFinishRequest) (*service.AuthenticationResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthenticationResult), args.Error(1)
}

func (m *mockWebAuthnService) GetUserCredentials(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.WebAuthnCredential), args.Error(1)
}

func (m *mockWebAuthnService) UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	args := m.Called(ctx, credential)
	return args.Error(0)
}

func (m *mockWebAuthnService) DeleteCredential(ctx context.Context, userID string, credentialID []byte) error {
	args := m.Called(ctx, userID, credentialID)
	return args.Error(0)
}

func (m *mockWebAuthnService) GetCredentialStatistics(ctx context.Context) (*service.CredentialStatistics, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.CredentialStatistics), args.Error(1)
}

func (m *mockWebAuthnService) CleanupExpiredData(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockWebAuthnService) ValidateCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error {
	args := m.Called(ctx, credentialID, signCount)
	return args.Error(0)
}

// Test helpers

func createTestRegistrationStartRequest() *service.RegistrationStartRequest {
	return &service.RegistrationStartRequest{
		UserID:      uuid.New().String(),
		Username:    "testuser",
		DisplayName: "Test User",
	}
}

func createTestRegistrationStartResponse() *service.RegistrationStartResponse {
	return &service.RegistrationStartResponse{
		SessionID: uuid.New().String(),
		CreationOptions: &models.PublicKeyCredentialCreationOptions{
			Challenge: []byte("test-challenge"),
			RP: &models.RelyingPartyEntity{
				ID:   "localhost",
				Name: "Test Service",
			},
			User: &models.UserEntity{
				ID:          []byte("test-user-id"),
				Name:        "testuser",
				DisplayName: "Test User",
			},
			PubKeyCredParams: models.DefaultCredentialParameters(),
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func createTestRegistrationFinishRequest() *service.RegistrationFinishRequest {
	return &service.RegistrationFinishRequest{
		SessionID: uuid.New().String(),
		AttestationResponse: &models.AuthenticatorAttestationResponse{
			ID:   "test-credential",
			Type: "public-key",
			RawID: []byte("test-credential"),
			Response: &models.AuthenticatorAttestationResponseData{
				ClientDataJSON:    []byte("test-client-data"),
				AttestationObject: []byte("test-attestation"),
			},
		},
	}
}

func createTestRegistrationResult() *service.RegistrationResult {
	return &service.RegistrationResult{
		Success:      true,
		CredentialID: "test-credential-id",
		Credential: &models.WebAuthnCredential{
			ID:           uuid.New().String(),
			UserID:       uuid.New().String(),
			CredentialID: []byte("test-credential-id"),
			PublicKey:    []byte("test-public-key"),
			AttestationType: "none",
			Transport: []models.AuthenticatorTransport{
				models.TransportUSB,
			},
			SignCount: 0,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

// Tests

func TestRegistrationHandler_StartRegistration(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:        "Valid_Registration_Start",
			requestBody: createTestRegistrationStartRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("BeginRegistration", mock.Anything, mock.AnythingOfType("*service.RegistrationStartRequest")).
					Return(createTestRegistrationStartResponse(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:        "Invalid_Request_Body",
			requestBody: "invalid json",
			setupMock:   func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Missing_Required_Fields",
			requestBody: &service.RegistrationStartRequest{
				// Missing UserID and Username
			},
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:        "Service_Error",
			requestBody: createTestRegistrationStartRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("BeginRegistration", mock.Anything, mock.AnythingOfType("*service.RegistrationStartRequest")).
					Return(nil, service.NewServiceError(service.ErrServiceInternal, "Internal error", ""))
			},
			expectedStatus: http.StatusInternalServerError,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := &mockWebAuthnService{}
			tt.setupMock(mockService)
			
			handler := NewRegistrationHandler(mockService)
			
			// Create request
			var body []byte
			var err error
			if tt.requestBody != nil {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}
			
			req := httptest.NewRequest("POST", "/webauthn/register/start", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.StartRegistration(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response service.RegistrationStartResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.NotEmpty(t, response.SessionID)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestRegistrationHandler_FinishRegistration(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:        "Valid_Registration_Finish",
			requestBody: createTestRegistrationFinishRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("FinishRegistration", mock.Anything, mock.AnythingOfType("*service.RegistrationFinishRequest")).
					Return(createTestRegistrationResult(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:        "Invalid_Request_Body",
			requestBody: "invalid json",
			setupMock:   func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Registration_Failed",
			requestBody: createTestRegistrationFinishRequest(),
			setupMock: func(m *mockWebAuthnService) {
				result := &service.RegistrationResult{
					Success: false,
					Error:   service.NewServiceError(service.ErrServiceValidation, "Invalid attestation", ""),
				}
				m.On("FinishRegistration", mock.Anything, mock.AnythingOfType("*service.RegistrationFinishRequest")).
					Return(result, nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := &mockWebAuthnService{}
			tt.setupMock(mockService)
			
			handler := NewRegistrationHandler(mockService)
			
			// Create request
			var body []byte
			var err error
			if tt.requestBody != nil {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}
			
			req := httptest.NewRequest("POST", "/webauthn/register/finish", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.FinishRegistration(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response service.RegistrationResult
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestRegistrationHandler_Routes(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewRegistrationHandler(mockService)
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test route registration
	req := httptest.NewRequest("POST", "/webauthn/register/start", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	// Should not be 404 (route exists)
	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}