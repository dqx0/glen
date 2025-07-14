package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/golang-jwt/jwt/v5"
)

func TestDebugJWT(t *testing.T) {
	// Create the same JWT config as the test
	jwtConfig := &middleware.JWTConfig{
		Secret:        []byte("test-secret-key"),
		SigningMethod: jwt.SigningMethodHS256,
		Expiration:    24 * time.Hour,
	}

	// Generate a token like the test does
	token, err := middleware.GenerateToken(jwtConfig, "test-user-id", false)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	fmt.Printf("Generated token: %s\n", token)
	fmt.Printf("Token length: %d\n", len(token))

	// Try to validate the token
	claims, err := middleware.ValidateToken(jwtConfig, token)
	if err != nil {
		t.Fatalf("Error validating token: %v", err)
	}

	fmt.Printf("Token validated successfully: %+v\n", claims)
}
