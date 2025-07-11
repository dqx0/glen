package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
)

func TestWebAuthnHandler_HealthCheck(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewWebAuthnHandler(mockService, middleware.DefaultJWTConfig())
	
	req := httptest.NewRequest("GET", "/webauthn/health", nil)
	rr := httptest.NewRecorder()
	
	handler.HealthCheck(rr, req)
	
	assert.Equal(t, http.StatusOK, rr.Code)
	
	var response HealthCheckResponse
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Equal(t, "healthy", response.Status)
	assert.Equal(t, "webauthn", response.Service)
	assert.Equal(t, "1.0.0", response.Version)
}

func TestWebAuthnHandler_RegisterRoutes(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewWebAuthnHandler(mockService, middleware.DefaultJWTConfig())
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test that health endpoint works without calling other services
	req := httptest.NewRequest("GET", "/webauthn/health", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	// Health endpoint should work
	assert.Equal(t, http.StatusOK, rr.Code)
	
	// Test that non-existent route returns 404
	req404 := httptest.NewRequest("GET", "/webauthn/nonexistent", nil)
	rr404 := httptest.NewRecorder()
	
	r.ServeHTTP(rr404, req404)
	assert.Equal(t, http.StatusNotFound, rr404.Code)
}

func TestWebAuthnHandler_CORS(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewWebAuthnHandler(mockService, middleware.DefaultJWTConfig())
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test OPTIONS request for CORS
	req := httptest.NewRequest("OPTIONS", "/webauthn/health", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Methods"))
	assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Headers"))
}

func TestWebAuthnHandler_ContentType(t *testing.T) {
	mockService := &mockWebAuthnService{}
	handler := NewWebAuthnHandler(mockService, middleware.DefaultJWTConfig())
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	req := httptest.NewRequest("GET", "/webauthn/health", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}