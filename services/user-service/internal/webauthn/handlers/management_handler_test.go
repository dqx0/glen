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

// Test helpers for management

func createTestWebAuthnCredentials() []*models.WebAuthnCredential {
	return []*models.WebAuthnCredential{
		{
			ID:           uuid.New().String(),
			UserID:       uuid.New().String(),
			CredentialID: []byte("test-credential-1"),
			PublicKey:    []byte("test-public-key-1"),
			AttestationType: "none",
			Transport: []models.AuthenticatorTransport{
				models.TransportUSB,
			},
			SignCount: 0,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:           uuid.New().String(),
			UserID:       uuid.New().String(),
			CredentialID: []byte("test-credential-2"),
			PublicKey:    []byte("test-public-key-2"),
			AttestationType: "none",
			Transport: []models.AuthenticatorTransport{
				models.TransportBLE,
			},
			SignCount: 5,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

func createTestCredentialStatistics() *service.CredentialStatistics {
	return &service.CredentialStatistics{
		TotalCredentials:     100,
		ActiveCredentials:    95,
		CredentialsByTransport: map[models.AuthenticatorTransport]int{
			models.TransportUSB: 60,
			models.TransportNFC: 25,
			models.TransportBLE: 15,
		},
		CredentialsByAttestation: map[string]int{
			"none": 80,
			"basic": 20,
		},
		AvgCredentialsPerUser: 2.5,
		CreatedInLast24Hours:  5,
		CreatedInLastWeek:     20,
		CreatedInLastMonth:    50,
		UsageStatistics: &service.CredentialUsageStatistics{
			TotalAuthentications:     1000,
			AuthenticationsLast24h:   50,
			AuthenticationsLastWeek:  200,
			AuthenticationsLastMonth: 500,
		},
	}
}

// Tests

func TestManagementHandler_GetUserCredentials(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:   "Valid_Get_Credentials",
			userID: uuid.New().String(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("GetUserCredentials", mock.Anything, mock.AnythingOfType("string")).
					Return(createTestWebAuthnCredentials(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Missing_User_ID",
			userID:         "",
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:   "Service_Error",
			userID: uuid.New().String(),
			setupMock: func(m *mockWebAuthnService) {
				m.On("GetUserCredentials", mock.Anything, mock.AnythingOfType("string")).
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
			
			handler := NewManagementHandler(mockService)
			
			// Create request
			url := "/webauthn/credentials/" + tt.userID
			req := httptest.NewRequest("GET", url, nil)
			
			// Set URL parameters
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("userID", tt.userID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.GetUserCredentials(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response GetCredentialsResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
				assert.Equal(t, 2, response.Count)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestManagementHandler_DeleteCredential(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		credentialID   string
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name:         "Valid_Delete_Credential",
			userID:       uuid.New().String(),
			credentialID: "test-credential-id",
			setupMock: func(m *mockWebAuthnService) {
				m.On("DeleteCredential", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).
					Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Missing_User_ID",
			userID:         "",
			credentialID:   "test-credential-id",
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "Missing_Credential_ID",
			userID:         uuid.New().String(),
			credentialID:   "",
			setupMock:      func(m *mockWebAuthnService) {},
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:         "Service_Error",
			userID:       uuid.New().String(),
			credentialID: "test-credential-id",
			setupMock: func(m *mockWebAuthnService) {
				m.On("DeleteCredential", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).
					Return(service.NewServiceError(service.ErrServiceNotFound, "Credential not found", ""))
			},
			expectedStatus: http.StatusNotFound,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := &mockWebAuthnService{}
			tt.setupMock(mockService)
			
			handler := NewManagementHandler(mockService)
			
			// Create request
			url := "/webauthn/credentials/" + tt.userID + "/" + tt.credentialID
			req := httptest.NewRequest("DELETE", url, nil)
			
			// Set URL parameters
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("userID", tt.userID)
			rctx.URLParams.Add("credentialID", tt.credentialID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.DeleteCredential(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response SuccessResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestManagementHandler_UpdateCredential(t *testing.T) {
	userID := uuid.New().String()
	credentialID := "test-credential-id"
	
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid_Update_Credential",
			requestBody: &UpdateCredentialRequest{
				CloneWarning: &[]bool{true}[0],
			},
			setupMock: func(m *mockWebAuthnService) {
				credentials := createTestWebAuthnCredentials()
				// Set the credential ID to match what we're looking for
				credentials[0].CredentialID = []byte(credentialID)
				
				m.On("GetUserCredentials", mock.Anything, userID).
					Return(credentials, nil)
				m.On("UpdateCredential", mock.Anything, mock.AnythingOfType("*models.WebAuthnCredential")).
					Return(nil)
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
			name: "Credential_Not_Found",
			requestBody: &UpdateCredentialRequest{
				CloneWarning: &[]bool{true}[0],
			},
			setupMock: func(m *mockWebAuthnService) {
				// Return credentials but none match the credential ID
				m.On("GetUserCredentials", mock.Anything, userID).
					Return(createTestWebAuthnCredentials(), nil)
			},
			expectedStatus: http.StatusNotFound,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := &mockWebAuthnService{}
			tt.setupMock(mockService)
			
			handler := NewManagementHandler(mockService)
			
			// Create request
			var body []byte
			var err error
			if tt.requestBody != nil {
				body, err = json.Marshal(tt.requestBody)
				require.NoError(t, err)
			}
			
			url := "/webauthn/credentials/" + userID + "/" + credentialID
			req := httptest.NewRequest("PUT", url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			
			// Set URL parameters
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("userID", userID)
			rctx.URLParams.Add("credentialID", credentialID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			
			rr := httptest.NewRecorder()
			
			// Execute
			handler.UpdateCredential(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response SuccessResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestManagementHandler_GetStatistics(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid_Get_Statistics",
			setupMock: func(m *mockWebAuthnService) {
				m.On("GetCredentialStatistics", mock.Anything).
					Return(createTestCredentialStatistics(), nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Service_Error",
			setupMock: func(m *mockWebAuthnService) {
				m.On("GetCredentialStatistics", mock.Anything).
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
			
			handler := NewManagementHandler(mockService)
			
			req := httptest.NewRequest("GET", "/webauthn/admin/statistics", nil)
			rr := httptest.NewRecorder()
			
			// Execute
			handler.GetStatistics(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response StatisticsResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
				assert.NotNil(t, response.Statistics)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestManagementHandler_CleanupExpiredData(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mockWebAuthnService)
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid_Cleanup",
			setupMock: func(m *mockWebAuthnService) {
				m.On("CleanupExpiredData", mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Service_Error",
			setupMock: func(m *mockWebAuthnService) {
				m.On("CleanupExpiredData", mock.Anything).
					Return(service.NewServiceError(service.ErrServiceInternal, "Internal error", ""))
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
			
			handler := NewManagementHandler(mockService)
			
			req := httptest.NewRequest("POST", "/webauthn/admin/cleanup", nil)
			rr := httptest.NewRecorder()
			
			// Execute
			handler.CleanupExpiredData(rr, req)
			
			// Assert
			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			if tt.expectError {
				var errorResp ErrorResponse
				err := json.Unmarshal(rr.Body.Bytes(), &errorResp)
				require.NoError(t, err)
				assert.NotEmpty(t, errorResp.Error)
			} else {
				var response SuccessResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.Success)
			}
			
			mockService.AssertExpectations(t)
		})
	}
}

func TestManagementHandler_Routes(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewManagementHandler(mockService)
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test route registration without actually calling the handlers
	// by testing a non-existent route
	req := httptest.NewRequest("GET", "/webauthn/nonexistent", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	// Should be 404 (route doesn't exist)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}