package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/dqx0/glen/api-gateway/internal/service"
)

func TestGatewayHandler_HealthCheck(t *testing.T) {
	// モックサービスを作成
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"healthy":true}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	config := &service.Config{
		UserService:   mockServer.URL,
		AuthService:   mockServer.URL,
		SocialService: mockServer.URL,
	}
	
	serviceProxy := service.NewServiceProxy(config)
	handler := NewGatewayHandler(serviceProxy)

	t.Run("health check returns OK when all services are healthy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		handler.HealthCheck(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	t.Run("health check returns method not allowed for non-GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		w := httptest.NewRecorder()

		handler.HealthCheck(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestGatewayHandler_APIInfo(t *testing.T) {
	config := &service.Config{
		UserService:   "http://localhost:8081",
		AuthService:   "http://localhost:8082", 
		SocialService: "http://localhost:8083",
	}
	
	serviceProxy := service.NewServiceProxy(config)
	handler := NewGatewayHandler(serviceProxy)

	t.Run("API info returns OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/info", nil)
		w := httptest.NewRecorder()

		handler.APIInfo(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	t.Run("API info returns method not allowed for non-GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/info", nil)
		w := httptest.NewRecorder()

		handler.APIInfo(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expected    string
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer abc123",
			expected:   "abc123",
		},
		{
			name:       "empty header",
			authHeader: "",
			expected:   "",
		},
		{
			name:       "invalid format",
			authHeader: "Basic abc123",
			expected:   "",
		},
		{
			name:       "bearer without token",
			authHeader: "Bearer ",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBearerToken(tt.authHeader)
			assert.Equal(t, tt.expected, result)
		})
	}
}