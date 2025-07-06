package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware_Handle(t *testing.T) {
	middleware := NewAuthMiddleware("http://localhost:8082")
	
	// テスト用のハンドラー
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "authorization header required")
	})

	t.Run("valid JWT token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})

	t.Run("valid API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey sk_test_1234567890abcdef1234567890abcdef")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})

	t.Run("unsupported authorization type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "unsupported authorization type")
	})

	t.Run("invalid JWT token format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid JWT token")
	})

	t.Run("short API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey short")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid API key")
	})
}

func TestAuthMiddleware_RequireAPIKey(t *testing.T) {
	middleware := NewAuthMiddleware("http://localhost:8082")
	
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}

	t.Run("missing API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "API key required")
	})

	t.Run("wrong format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "API key format")
	})

	t.Run("valid API key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey sk_test_1234567890abcdef1234567890abcdef")
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})
}

func TestAuthMiddleware_RequireJWT(t *testing.T) {
	middleware := NewAuthMiddleware("http://localhost:8082")
	
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}

	t.Run("missing JWT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler := middleware.RequireJWT(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "JWT token required")
	})

	t.Run("wrong format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey key")
		w := httptest.NewRecorder()

		handler := middleware.RequireJWT(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "JWT format")
	})

	t.Run("valid JWT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature")
		w := httptest.NewRecorder()

		handler := middleware.RequireJWT(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})
}