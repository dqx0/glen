package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockHTTPClient はHTTPClientのモック
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestAuthMiddleware_Handle(t *testing.T) {
	// テスト用のハンドラー
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}

	t.Run("missing authorization header", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "authorization header required")
	})

	t.Run("valid JWT token", func(t *testing.T) {
		mockClient := new(MockHTTPClient)
		middleware := NewAuthMiddlewareWithClient("http://localhost:8082", mockClient)

		// JWTトークンの検証が成功するようにモック設定
		successResponse := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"valid": true, "user_id": "test-user"}`)),
		}
		mockClient.On("Do", mock.AnythingOfType("*http.Request")).Return(successResponse, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
		mockClient.AssertExpectations(t)
	})

	t.Run("valid API key", func(t *testing.T) {
		mockClient := new(MockHTTPClient)
		middleware := NewAuthMiddlewareWithClient("http://localhost:8082", mockClient)

		// APIキーの検証が成功するようにモック設定（2回の呼び出しに対応）
		successResponse := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"user_id": "test-user"}`)),
		}
		// validateAPIKey と extractUserIDFromAPIKey の両方でHTTPクライアントが使用される
		mockClient.On("Do", mock.AnythingOfType("*http.Request")).Return(successResponse, nil).Times(2)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey sk_test_1234567890abcdef1234567890abcdef")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
		mockClient.AssertExpectations(t)
	})

	t.Run("unsupported authorization type", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "unsupported authorization type")
	})

	t.Run("invalid JWT token format", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid")
		w := httptest.NewRecorder()

		handler := middleware.Handle(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid JWT token")
	})

	t.Run("short API key", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

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
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}

	t.Run("missing API key", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "API key required")
	})

	t.Run("wrong format", func(t *testing.T) {
		middleware := NewAuthMiddleware("http://localhost:8082")

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer token")
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "API key format")
	})

	t.Run("valid API key", func(t *testing.T) {
		mockClient := new(MockHTTPClient)
		middleware := NewAuthMiddlewareWithClient("http://localhost:8082", mockClient)

		// APIキーの検証が成功するようにモック設定（validateAPIKey用）
		successResponse := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"valid": true}`)),
		}
		mockClient.On("Do", mock.AnythingOfType("*http.Request")).Return(successResponse, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "ApiKey sk_test_1234567890abcdef1234567890abcdef")
		w := httptest.NewRecorder()

		handler := middleware.RequireAPIKey(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
		mockClient.AssertExpectations(t)
	})
}

func TestAuthMiddleware_RequireJWT(t *testing.T) {
	mockClient := new(MockHTTPClient)
	middleware := NewAuthMiddlewareWithClient("http://localhost:8082", mockClient)

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
		// JWTトークンの検証が成功するようにモック設定
		successResponse := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"valid": true, "user_id": "test-user"}`)),
		}
		mockClient.On("Do", mock.AnythingOfType("*http.Request")).Return(successResponse, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature")
		w := httptest.NewRecorder()

		handler := middleware.RequireJWT(testHandler)
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
		mockClient.AssertExpectations(t)
	})
}
