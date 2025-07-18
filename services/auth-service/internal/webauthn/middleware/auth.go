package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	authService "github.com/dqx0/glen/auth-service/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// AuthContextKey is the key for storing auth context
type AuthContextKey string

const (
	UserIDKey  AuthContextKey = "user_id"
	IsAdminKey AuthContextKey = "is_admin"
)

// JWTConfig holds JWT configuration compatible with auth-service
type JWTConfig struct {
	jwtService    *authService.JWTService
	Secret        []byte            `json:"secret"`         // For backward compatibility with tests
	SigningMethod jwt.SigningMethod `json:"signing_method"` // For backward compatibility with tests
	Expiration    time.Duration     `json:"expiration"`     // For backward compatibility with tests
}

// NewJWTConfig creates a new JWT configuration using auth-service JWT service
func NewJWTConfig(jwtService *authService.JWTService) *JWTConfig {
	return &JWTConfig{
		jwtService: jwtService,
	}
}

// ValidateToken validates a JWT token using auth-service JWT service
func (c *JWTConfig) ValidateToken(tokenString string) (*authService.Claims, error) {
	if c.jwtService != nil {
		return c.jwtService.ValidateToken(tokenString)
	}

	// Fallback to test implementation
	claims, err := ValidateToken(c, tokenString)
	if err != nil {
		return nil, err
	}

	// Convert AuthClaims to authService.Claims
	scopes := []string{}
	if claims.IsAdmin {
		scopes = append(scopes, "admin")
	}
	return &authService.Claims{
		UserID: claims.UserID,
		Scopes: scopes,
	}, nil
}

// JWTMiddleware provides JWT authentication middleware using auth-service
func JWTMiddleware(config *JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Extract token from "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims, err := config.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Check if user has admin scope
			isAdmin := false
			for _, scope := range claims.Scopes {
				if scope == "admin" {
					isAdmin = true
					break
				}
			}

			// Add claims to request context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, IsAdminKey, isAdmin)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin middleware ensures the user has admin privileges
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := r.Context().Value(IsAdminKey).(bool)
		if !ok || !isAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireOwnerOrAdmin middleware ensures the user owns the resource or is admin
func RequireOwnerOrAdmin(userIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "User not authenticated", http.StatusUnauthorized)
				return
			}

			isAdmin, _ := r.Context().Value(IsAdminKey).(bool)

			// Extract user ID from URL parameters using chi
			requestedUserID := chi.URLParam(r, userIDParam)

			// Fallback to query parameter if URL param not found
			if requestedUserID == "" {
				requestedUserID = r.URL.Query().Get(userIDParam)
			}

			// Allow if user is admin or accessing their own resources
			if !isAdmin && userID != requestedUserID {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserID extracts user ID from request context
func GetUserID(r *http.Request) (string, bool) {
	// 複数の方法でユーザーIDを取得を試みる

	// 1. コンテキストから取得（認証ミドルウェアが設定）
	if userID := r.Context().Value("user_id"); userID != nil {
		if uid, ok := userID.(string); ok && uid != "" {
			return uid, true
		}
	}

	// 2. ヘッダーから取得（API Gatewayが設定）
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID, true
	}

	// 3. JWTトークンから取得（直接デコード）
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if userID := extractUserIDFromJWT(token); userID != "" {
			return userID, true
		}
	}

	return "", false
}

// extractUserIDFromJWT はJWTトークンからユーザーIDを抽出（簡易版、署名検証なし）
func extractUserIDFromJWT(token string) string {
	// JWT形式: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	// ペイロード部分をデコード
	payload := parts[1]
	// Base64 URL デコード用にパディングを追加
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	// JSONをパース
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}

	// user_idを取得
	if userID, ok := claims["user_id"].(string); ok {
		return userID
	}

	return ""
}

// IsAdmin checks if the user has admin privileges
func IsAdmin(r *http.Request) bool {
	isAdmin, ok := r.Context().Value(IsAdminKey).(bool)
	return ok && isAdmin
}

// Development mode helper functions

// isDevMode checks if we're running in development mode
func isDevMode() bool {
	env := os.Getenv("ENVIRONMENT")
	return env == "development" || env == "dev" || env == ""
}

// DevModeMiddleware provides a development-only bypass for authentication
func DevModeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In dev mode, get user ID from X-User-ID header (set by API Gateway auth middleware)
		userID := r.Header.Get("X-User-ID")

		// If no user ID is present, this means the user is not authenticated
		if userID == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, IsAdminKey, false)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DevModeAdminMiddleware provides a development-only bypass for admin authentication
func DevModeAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In dev mode, get user ID from X-User-ID header (set by API Gateway auth middleware)
		userID := r.Header.Get("X-User-ID")

		// If no user ID is present, this means the user is not authenticated
		if userID == "" {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		// In dev mode, only specific admin user IDs are treated as admin
		// Check if this is an admin user (based on admin user ID pattern or specific IDs)
		isAdmin := false
		adminTestUserID := "87654321-4321-4321-9876-ba9876543210" // Admin test user ID
		if userID == adminTestUserID {
			isAdmin = true
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, IsAdminKey, isAdmin)

		// If admin privileges are required but user is not admin, deny access
		if !isAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthClaims represents JWT claims for WebAuthn middleware compatibility
type AuthClaims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

// DefaultJWTConfig creates a default JWT configuration for testing
func DefaultJWTConfig() *JWTConfig {
	// This should be integrated with auth-service's JWT service in production
	// For now, create a basic config for testing
	return &JWTConfig{
		jwtService:    nil, // Will use direct JWT operations for testing
		Secret:        []byte("test-secret-key-for-webauthn-middleware"),
		SigningMethod: jwt.SigningMethodHS256,
		Expiration:    24 * time.Hour,
	}
}

// GenerateToken generates a JWT token for testing purposes
func GenerateToken(config *JWTConfig, userID string, isAdmin bool) (string, error) {
	// For testing, use direct JWT operations
	expiration := config.Expiration
	if expiration == 0 {
		expiration = 24 * time.Hour
	}

	claims := AuthClaims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	signingMethod := config.SigningMethod
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodHS256
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	secret := config.Secret
	if len(secret) == 0 {
		secret = []byte("test-secret-key-for-webauthn-middleware")
	}

	return token.SignedString(secret)
}

// ValidateToken validates a JWT token for testing purposes
func ValidateToken(config *JWTConfig, tokenString string) (*AuthClaims, error) {
	// For testing, use direct JWT operations
	secret := config.Secret
	if len(secret) == 0 {
		secret = []byte("test-secret-key-for-webauthn-middleware")
	}

	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}
