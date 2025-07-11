package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	config := DefaultJWTConfig()
	userID := "test-user-123"
	isAdmin := true

	token, err := GenerateToken(config, userID, isAdmin)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token can be parsed
	claims, err := ValidateToken(config, token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, isAdmin, claims.IsAdmin)
}

func TestValidateToken(t *testing.T) {
	config := DefaultJWTConfig()
	userID := "test-user-123"
	isAdmin := false

	tests := []struct {
		name        string
		tokenFunc   func() string
		expectError bool
	}{
		{
			name: "Valid_Token",
			tokenFunc: func() string {
				token, _ := GenerateToken(config, userID, isAdmin)
				return token
			},
			expectError: false,
		},
		{
			name: "Invalid_Token",
			tokenFunc: func() string {
				return "invalid.token.here"
			},
			expectError: true,
		},
		{
			name: "Expired_Token",
			tokenFunc: func() string {
				// Create an expired token
				claims := AuthClaims{
					UserID:  userID,
					IsAdmin: isAdmin,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
						NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					},
				}
				token := jwt.NewWithClaims(config.SigningMethod, claims)
				tokenString, _ := token.SignedString(config.Secret)
				return tokenString
			},
			expectError: true,
		},
		{
			name: "Wrong_Secret",
			tokenFunc: func() string {
				wrongConfig := &JWTConfig{
					Secret:        []byte("wrong-secret"),
					SigningMethod: jwt.SigningMethodHS256,
					Expiration:    24 * time.Hour,
				}
				token, _ := GenerateToken(wrongConfig, userID, isAdmin)
				return token
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.tokenFunc()
			claims, err := ValidateToken(config, token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Equal(t, userID, claims.UserID)
				assert.Equal(t, isAdmin, claims.IsAdmin)
			}
		})
	}
}

func TestJWTMiddleware(t *testing.T) {
	config := DefaultJWTConfig()
	middleware := JWTMiddleware(config)

	// Create a test handler that checks if auth context is set
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r)
		if !ok {
			http.Error(w, "User ID not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-User-ID", userID)
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(testHandler)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectUserID   bool
	}{
		{
			name:           "Valid_Token",
			authHeader:     createValidAuthHeader(config, "test-user", false),
			expectedStatus: http.StatusOK,
			expectUserID:   true,
		},
		{
			name:           "Missing_Header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
		{
			name:           "Invalid_Header_Format",
			authHeader:     "InvalidFormat token",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
		{
			name:           "Invalid_Token",
			authHeader:     "Bearer invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			expectUserID:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectUserID {
				assert.Equal(t, "test-user", rr.Header().Get("X-User-ID"))
			}
		})
	}
}

func TestRequireAdmin(t *testing.T) {
	config := DefaultJWTConfig()
	jwtMiddleware := JWTMiddleware(config)
	adminMiddleware := RequireAdmin

	// Test handler that returns 200 if admin check passes
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Chain middlewares
	handler := jwtMiddleware(adminMiddleware(testHandler))

	tests := []struct {
		name           string
		isAdmin        bool
		expectedStatus int
	}{
		{
			name:           "Admin_User",
			isAdmin:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Regular_User",
			isAdmin:        false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin", nil)
			req.Header.Set("Authorization", createValidAuthHeader(config, "test-user", tt.isAdmin))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestRequireOwnerOrAdmin(t *testing.T) {
	config := DefaultJWTConfig()
	jwtMiddleware := JWTMiddleware(config)
	ownerMiddleware := RequireOwnerOrAdmin("userID")

	// Test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Chain middlewares
	handler := jwtMiddleware(ownerMiddleware(testHandler))

	tests := []struct {
		name           string
		userID         string
		requestedID    string
		isAdmin        bool
		expectedStatus int
	}{
		{
			name:           "Owner_Access",
			userID:         "user-123",
			requestedID:    "user-123",
			isAdmin:        false,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Admin_Access",
			userID:         "admin-user",
			requestedID:    "any-user",
			isAdmin:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Unauthorized_Access",
			userID:         "user-123",
			requestedID:    "user-456",
			isAdmin:        false,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/credentials/"+tt.requestedID+"?userID="+tt.requestedID, nil)
			req.Header.Set("Authorization", createValidAuthHeader(config, tt.userID, tt.isAdmin))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestGetUserID(t *testing.T) {
	config := DefaultJWTConfig()
	middleware := JWTMiddleware(config)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := GetUserID(r)
		if ok {
			w.Header().Set("X-User-ID", userID)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", createValidAuthHeader(config, "test-user-123", false))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "test-user-123", rr.Header().Get("X-User-ID"))
}

func TestIsAdmin(t *testing.T) {
	config := DefaultJWTConfig()
	middleware := JWTMiddleware(config)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsAdmin(r) {
			w.Header().Set("X-Is-Admin", "true")
		} else {
			w.Header().Set("X-Is-Admin", "false")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(testHandler)

	tests := []struct {
		name     string
		isAdmin  bool
		expected string
	}{
		{
			name:     "Admin_User",
			isAdmin:  true,
			expected: "true",
		},
		{
			name:     "Regular_User",
			isAdmin:  false,
			expected: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", createValidAuthHeader(config, "test-user", tt.isAdmin))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, tt.expected, rr.Header().Get("X-Is-Admin"))
		})
	}
}

// Helper function to create valid authorization header
func createValidAuthHeader(config *JWTConfig, userID string, isAdmin bool) string {
	token, _ := GenerateToken(config, userID, isAdmin)
	return "Bearer " + token
}