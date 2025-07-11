package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// AuthContextKey is the key for storing auth context
type AuthContextKey string

const (
	UserIDKey  AuthContextKey = "user_id"
	IsAdminKey AuthContextKey = "is_admin"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret     []byte
	SigningMethod jwt.SigningMethod
	Expiration time.Duration
}

// DefaultJWTConfig returns default JWT configuration
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Secret:        []byte("your-secret-key"), // Should be from environment
		SigningMethod: jwt.SigningMethodHS256,
		Expiration:    24 * time.Hour,
	}
}

// AuthClaims represents JWT claims
type AuthClaims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT token for a user
func GenerateToken(config *JWTConfig, userID string, isAdmin bool) (string, error) {
	claims := AuthClaims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.Expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "glen-webauthn",
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(config.SigningMethod, claims)
	return token.SignedString(config.Secret)
}

// ValidateToken validates a JWT token and returns claims
func ValidateToken(config *JWTConfig, tokenString string) (*AuthClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != config.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return config.Secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*AuthClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// JWTMiddleware provides JWT authentication middleware
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
			claims, err := ValidateToken(config, tokenString)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Add claims to request context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, IsAdminKey, claims.IsAdmin)
			
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
	userID, ok := r.Context().Value(UserIDKey).(string)
	return userID, ok
}

// IsAdmin checks if the user has admin privileges
func IsAdmin(r *http.Request) bool {
	isAdmin, ok := r.Context().Value(IsAdminKey).(bool)
	return ok && isAdmin
}