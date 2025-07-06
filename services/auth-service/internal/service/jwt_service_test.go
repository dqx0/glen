package service

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_GenerateAccessToken(t *testing.T) {
	// テスト用のRSA鍵ペアを使用
	privateKey, publicKey := generateTestKeyPair(t)
	
	service, err := NewJWTService(privateKey, publicKey)
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		userID   string
		username string
		scopes   []string
		wantErr  bool
	}{
		{
			name:     "valid token generation",
			userID:   "user-123",
			username: "testuser",
			scopes:   []string{"user:read", "user:write"},
			wantErr:  false,
		},
		{
			name:     "minimal scopes",
			userID:   "user-456",
			username: "testuser2",
			scopes:   []string{"user:read"},
			wantErr:  false,
		},
		{
			name:     "invalid - empty user ID",
			userID:   "",
			username: "testuser",
			scopes:   []string{"user:read"},
			wantErr:  true,
		},
		{
			name:     "invalid - empty username",
			userID:   "user-123",
			username: "",
			scopes:   []string{"user:read"},
			wantErr:  true,
		},
		{
			name:     "invalid - empty scopes",
			userID:   "user-123",
			username: "testuser",
			scopes:   []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, jwtID, err := service.GenerateAccessToken(tt.userID, tt.username, tt.scopes)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, tokenString)
				assert.Empty(t, jwtID)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, tokenString)
				assert.NotEmpty(t, jwtID)
				
				// JWTの形式確認（3つの部分がドットで区切られている）
				parts := strings.Split(tokenString, ".")
				assert.Len(t, parts, 3)
			}
		})
	}
}

func TestJWTService_ValidateToken(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	service, err := NewJWTService(privateKey, publicKey)
	require.NoError(t, err)
	
	// 有効なトークンを生成
	validToken, jwtID, err := service.GenerateAccessToken("user-123", "testuser", []string{"user:read", "user:write"})
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		tokenString string
		wantErr     bool
		wantClaims  bool
	}{
		{
			name:        "valid token",
			tokenString: validToken,
			wantErr:     false,
			wantClaims:  true,
		},
		{
			name:        "invalid token format",
			tokenString: "invalid.token.format",
			wantErr:     true,
			wantClaims:  false,
		},
		{
			name:        "empty token",
			tokenString: "",
			wantErr:     true,
			wantClaims:  false,
		},
		{
			name:        "malformed token",
			tokenString: "not.a.jwt",
			wantErr:     true,
			wantClaims:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := service.ValidateToken(tt.tokenString)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				require.NoError(t, err)
				require.NotNil(t, claims)
				
				if tt.wantClaims {
					assert.Equal(t, "user-123", claims.UserID)
					assert.Equal(t, "testuser", claims.Username)
					assert.Equal(t, []string{"user:read", "user:write"}, claims.Scopes)
					assert.Equal(t, jwtID, claims.ID)
					assert.Equal(t, "glen-auth-service", claims.Issuer)
					assert.Equal(t, "glen-services", claims.Audience[0])
					assert.False(t, claims.ExpiresAt.Time.IsZero())
					assert.False(t, claims.IssuedAt.Time.IsZero())
				}
			}
		})
	}
}

func TestJWTService_TokenExpiry(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	service, err := NewJWTService(privateKey, publicKey)
	require.NoError(t, err)
	
	tokenString, _, err := service.GenerateAccessToken("user-123", "testuser", []string{"user:read"})
	require.NoError(t, err)
	
	claims, err := service.ValidateToken(tokenString)
	require.NoError(t, err)
	
	// トークンの有効期限が15分後に設定されているか確認
	expectedExpiry := time.Now().Add(15 * time.Minute)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, time.Minute)
	
	// トークンがまだ有効であることを確認
	assert.False(t, time.Now().After(claims.ExpiresAt.Time))
}

func TestJWTService_InvalidKeys(t *testing.T) {
	tests := []struct {
		name       string
		privateKey interface{}
		publicKey  interface{}
		wantErr    bool
	}{
		{
			name:       "nil private key",
			privateKey: nil,
			publicKey:  func() interface{} { _, pub := generateTestKeyPair(t); return pub }(),
			wantErr:    true,
		},
		{
			name:       "nil public key", 
			privateKey: func() interface{} { priv, _ := generateTestKeyPair(t); return priv }(),
			publicKey:  nil,
			wantErr:    true,
		},
		{
			name:       "both nil",
			privateKey: nil,
			publicKey:  nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewJWTService(tt.privateKey, tt.publicKey)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// generateTestKeyPair はテスト用のRSA鍵ペアを生成する
func generateTestKeyPair(t *testing.T) (privateKey, publicKey interface{}) {
	privKey, pubKey, err := GenerateTestKeyPair()
	require.NoError(t, err)
	return privKey, pubKey
}