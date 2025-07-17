package handlers

import (
	"bytes"
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

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// Test helpers for authentication

func createTestAuthenticationStartRequest() *service.AuthenticationStartRequest {
	return &service.AuthenticationStartRequest{
		UserID:         uuid.New().String(),
		UserIdentifier: "testuser",
	}
}

func createTestAuthenticationStartResponse() *service.AuthenticationStartResponse {
	return &service.AuthenticationStartResponse{
		SessionID: uuid.New().String(),
		RequestOptions: &models.PublicKeyCredentialRequestOptions{
			Challenge:        []byte("test-challenge"),
			UserVerification: models.UserVerificationPreferred,
			RPID:             "localhost",
		},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func createTestAuthenticationFinishRequest() *service.AuthenticationFinishRequest {
	return &service.AuthenticationFinishRequest{
		SessionID: uuid.New().String(),
		AssertionResponse: &models.AuthenticatorAssertionResponse{
			ID:    "test-credential",
			Type:  "public-key",
			RawID: []byte("test-credential"),
			Response: &models.AuthenticatorAssertionResponseData{
				ClientDataJSON:    []byte("test-client-data"),
				AuthenticatorData: []byte("test-authenticator-data"),
				Signature:         []byte("test-signature"),
			},
		},
	}
}

func createTestAuthenticationResult() *service.AuthenticationResult {
	return &service.AuthenticationResult{
		Success:            true,
		UserID:             uuid.New().String(),
		CredentialID:       "test-credential-id",
		AuthenticationTime: time.Now(),
		Warnings:           []string{},
	}
}

// Tests

func TestAuthenticationHandler_StartAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:        "Valid_Authentication_Start",
			requestBody: createTestAuthenticationStartRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("BeginAuthentication", mock.Anything, mock.AnythingOfType("*service.AuthenticationStartRequest")).
					Return(createTestAuthenticationStartResponse(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Invalid_Request_Body",
			requestBody:    "invalid json",
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Passwordless_Authentication_Request",
			requestBody: &service.AuthenticationStartRequest{
				// Empty UserID and UserIdentifier for passwordless authentication
			},
			setupMock: func(m *mockWebAuthnService) {
				m.On("BeginAuthentication", mock.Anything, mock.AnythingOfType("*service.AuthenticationStartRequest")).
					Return(createTestAuthenticationStartResponse(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:        "Service_Error",
			requestBody: createTestAuthenticationStartRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("BeginAuthentication", mock.Anything, mock.AnythingOfType("*service.AuthenticationStartRequest")).
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
			
			handler := NewAuthenticationHandler(mockService, middleware.DefaultJWTConfig())
			
			// Create request
			var body []byte
			var err error
			if tt.requestBody != nil {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}
			
			req := httptest.NewRequest("POST", "/webauthn/authenticate/start", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.StartAuthentication(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response service.AuthenticationStartResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.NotEmpty(t, response.SessionID)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthenticationHandler_FinishAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:        "Valid_Authentication_Finish",
			requestBody: createTestAuthenticationFinishRequest(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("FinishAuthentication", mock.Anything, mock.AnythingOfType("*service.AuthenticationFinishRequest")).
					Return(createTestAuthenticationResult(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Invalid_Request_Body",
			requestBody:    "invalid json",
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name: "Authentication_Failed",
			requestBody: createTestAuthenticationFinishRequest(),
			setupMock: func(m *mockWebAuthnService) {
				result := &service.AuthenticationResult{
					Success: false,
					Error:   service.NewServiceError(service.ErrServiceValidation, "Invalid assertion", ""),
				}
				m.On("FinishAuthentication", mock.Anything, mock.AnythingOfType("*service.AuthenticationFinishRequest")).
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
			
			handler := NewAuthenticationHandler(mockService, middleware.DefaultJWTConfig())
			
			// Create request
			var body []byte
			var err error
			if tt.requestBody != nil {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}
			
			req := httptest.NewRequest("POST", "/webauthn/authenticate/finish", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.FinishAuthentication(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response AuthenticationSuccessResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthenticationHandler_Routes(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewAuthenticationHandler(mockService, middleware.DefaultJWTConfig())
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test route registration
	req := httptest.NewRequest("POST", "/webauthn/authenticate/start", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	// Should not be 404 (route exists)
	assert.NotEqual(t, http.StatusNotFound, rr.Code)
}