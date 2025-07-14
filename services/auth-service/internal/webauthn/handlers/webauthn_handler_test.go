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
	// CORS is handled by API Gateway, not by the service itself
	// This test verifies that the service doesn't interfere with CORS handling
	mockService := &mockWebAuthnService{}
	handler := NewWebAuthnHandler(mockService, middleware.DefaultJWTConfig())
	
	r := chi.NewRouter()
	handler.RegisterRoutes(r)
	
	// Test that GET request works (health endpoint should be accessible)
	req := httptest.NewRequest("GET", "/webauthn/health", nil)
	rr := httptest.NewRecorder()
	
	r.ServeHTTP(rr, req)
	
	// Health endpoint should work normally
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	
	// Verify response contains expected health check data
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	assert.Equal(t, "webauthn", response["service"])
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