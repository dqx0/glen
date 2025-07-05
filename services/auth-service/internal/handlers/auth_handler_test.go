package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/auth-service/internal/models"
	"github.com/dqx0/glen/auth-service/internal/service"
)

// MockAuthService はAuthServiceのモック
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, userID, username, sessionName string, scopes []string) (*service.LoginResponse, error) {
	args := m.Called(ctx, userID, username, sessionName, scopes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.LoginResponse), args.Error(1)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshTokenValue, username string) (*service.RefreshResponse, error) {
	args := m.Called(ctx, refreshTokenValue, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.RefreshResponse), args.Error(1)
}

func (m *MockAuthService) CreateAPIKey(ctx context.Context, userID, name string, scopes []string) (*service.APIKeyResponse, error) {
	args := m.Called(ctx, userID, name, scopes)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.APIKeyResponse), args.Error(1)
}

func (m *MockAuthService) RevokeToken(ctx context.Context, tokenID, userID string) error {
	args := m.Called(ctx, tokenID, userID)
	return args.Error(0)
}

func (m *MockAuthService) ListUserTokens(ctx context.Context, userID string) ([]*models.Token, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Token), args.Error(1)
}

func (m *MockAuthService) ValidateAPIKey(ctx context.Context, apiKeyValue string) (*models.Token, error) {
	args := m.Called(ctx, apiKeyValue)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockAuthService) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func TestAuthHandler_Login(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	t.Run("successful login", func(t *testing.T) {
		loginReq := LoginRequest{
			UserID:      "user-123",
			Username:    "testuser",
			SessionName: "web-session",
			Scopes:      []string{"user:read", "user:write"},
		}

		expectedResponse := &service.LoginResponse{
			AccessToken:  "access.token.here",
			TokenType:    "Bearer",
			ExpiresIn:    900,
			RefreshToken: "refresh-token-here",
		}

		mockService.On("Login", mock.Anything, "user-123", "testuser", "web-session", []string{"user:read", "user:write"}).
			Return(expectedResponse, nil)

		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response service.LoginResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, expectedResponse.AccessToken, response.AccessToken)
		assert.Equal(t, expectedResponse.TokenType, response.TokenType)
		assert.Equal(t, expectedResponse.ExpiresIn, response.ExpiresIn)
		assert.Equal(t, expectedResponse.RefreshToken, response.RefreshToken)

		mockService.AssertExpectations(t)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing user ID", func(t *testing.T) {
		loginReq := LoginRequest{
			Username:    "testuser",
			SessionName: "web-session",
			Scopes:      []string{"user:read"},
		}

		mockService.On("Login", mock.Anything, "", "testuser", "web-session", []string{"user:read"}).
			Return(nil, service.ErrInvalidUserID)

		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	t.Run("successful token refresh", func(t *testing.T) {
		refreshReq := RefreshTokenRequest{
			RefreshToken: "refresh-token-value",
			Username:     "testuser",
		}

		expectedResponse := &service.RefreshResponse{
			AccessToken: "new.access.token",
			TokenType:   "Bearer",
			ExpiresIn:   900,
		}

		mockService.On("RefreshToken", mock.Anything, "refresh-token-value", "testuser").
			Return(expectedResponse, nil)

		reqBody, _ := json.Marshal(refreshReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RefreshToken(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response service.RefreshResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, expectedResponse.AccessToken, response.AccessToken)
		assert.Equal(t, expectedResponse.TokenType, response.TokenType)
		assert.Equal(t, expectedResponse.ExpiresIn, response.ExpiresIn)

		mockService.AssertExpectations(t)
	})

	t.Run("invalid refresh token", func(t *testing.T) {
		refreshReq := RefreshTokenRequest{
			RefreshToken: "invalid-token",
			Username:     "testuser",
		}

		mockService.On("RefreshToken", mock.Anything, "invalid-token", "testuser").
			Return(nil, service.ErrInvalidRefreshToken)

		reqBody, _ := json.Marshal(refreshReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RefreshToken(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAuthHandler_CreateAPIKey(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	t.Run("successful API key creation", func(t *testing.T) {
		createReq := CreateAPIKeyRequest{
			UserID: "user-123",
			Name:   "production-api",
			Scopes: []string{"api:read", "api:write"},
		}

		expectedResponse := &service.APIKeyResponse{
			ID:        "api-key-123",
			Name:      "production-api",
			Token:     "api-key-token-here",
			Scopes:    []string{"api:read", "api:write"},
			CreatedAt: time.Now(),
		}

		mockService.On("CreateAPIKey", mock.Anything, "user-123", "production-api", []string{"api:read", "api:write"}).
			Return(expectedResponse, nil)

		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/api-keys", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.CreateAPIKey(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response service.APIKeyResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, expectedResponse.ID, response.ID)
		assert.Equal(t, expectedResponse.Name, response.Name)
		assert.Equal(t, expectedResponse.Token, response.Token)
		assert.Equal(t, expectedResponse.Scopes, response.Scopes)

		mockService.AssertExpectations(t)
	})
}

func TestAuthHandler_RevokeToken(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)

	t.Run("successful token revocation", func(t *testing.T) {
		revokeReq := RevokeTokenRequest{
			TokenID: "token-123",
			UserID:  "user-123",
		}

		mockService.On("RevokeToken", mock.Anything, "token-123", "user-123").
			Return(nil)

		reqBody, _ := json.Marshal(revokeReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RevokeToken(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		mockService.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		revokeReq := RevokeTokenRequest{
			TokenID: "nonexistent-token",
			UserID:  "user-123",
		}

		mockService.On("RevokeToken", mock.Anything, "nonexistent-token", "user-123").
			Return(service.ErrTokenNotFound)

		reqBody, _ := json.Marshal(revokeReq)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RevokeToken(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}