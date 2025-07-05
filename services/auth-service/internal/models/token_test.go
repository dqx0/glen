package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken_NewRefreshToken(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		name     string
		scopes   []string
		wantErr  bool
	}{
		{
			name:    "valid refresh token",
			userID:  "user-123",
			name:    "login-session",
			scopes:  []string{"user:read", "user:write"},
			wantErr: false,
		},
		{
			name:    "valid refresh token with minimal scopes",
			userID:  "user-456",
			name:    "mobile-app",
			scopes:  []string{"user:read"},
			wantErr: false,
		},
		{
			name:    "invalid - empty user ID",
			userID:  "",
			name:    "session",
			scopes:  []string{"user:read"},
			wantErr: true,
		},
		{
			name:    "invalid - empty name",
			userID:  "user-123",
			name:    "",
			scopes:  []string{"user:read"},
			wantErr: true,
		},
		{
			name:    "invalid - empty scopes",
			userID:  "user-123",
			name:    "session",
			scopes:  []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := NewRefreshToken(tt.userID, tt.name, tt.scopes)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)
				
				assert.Equal(t, tt.userID, token.UserID)
				assert.Equal(t, tt.name, token.Name)
				assert.Equal(t, tt.scopes, token.Scopes)
				assert.Equal(t, TokenTypeRefresh, token.Type)
				assert.NotEmpty(t, token.ID)
				assert.NotEmpty(t, token.TokenHash)
				assert.False(t, token.CreatedAt.IsZero())
				assert.False(t, token.ExpiresAt.IsZero())
				assert.True(t, token.ExpiresAt.After(time.Now()))
				
				// Refresh tokenは30日後に期限切れ
				expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
				assert.WithinDuration(t, expectedExpiry, token.ExpiresAt, time.Minute)
			}
		})
	}
}

func TestToken_NewAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		name     string
		scopes   []string
		wantErr  bool
	}{
		{
			name:    "valid API key",
			userID:  "user-123",
			name:    "production-api",
			scopes:  []string{"api:read", "api:write"},
			wantErr: false,
		},
		{
			name:    "valid read-only API key",
			userID:  "user-456",
			name:    "monitoring",
			scopes:  []string{"api:read"},
			wantErr: false,
		},
		{
			name:    "invalid - empty user ID",
			userID:  "",
			name:    "api-key",
			scopes:  []string{"api:read"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := NewAPIKey(tt.userID, tt.name, tt.scopes)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
			} else {
				require.NoError(t, err)
				require.NotNil(t, token)
				
				assert.Equal(t, tt.userID, token.UserID)
				assert.Equal(t, tt.name, token.Name)
				assert.Equal(t, tt.scopes, token.Scopes)
				assert.Equal(t, TokenTypeAPIKey, token.Type)
				assert.NotEmpty(t, token.ID)
				assert.NotEmpty(t, token.TokenHash)
				assert.False(t, token.CreatedAt.IsZero())
				
				// API Keyは期限なし
				assert.True(t, token.ExpiresAt.IsZero())
			}
		})
	}
}

func TestToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			want:      true,
		},
		{
			name:      "no expiry (API key)",
			expiresAt: time.Time{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &Token{
				ExpiresAt: tt.expiresAt,
			}
			
			result := token.IsExpired()
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestToken_ValidateHash(t *testing.T) {
	token, err := NewRefreshToken("user-123", "test-session", []string{"user:read"})
	require.NoError(t, err)
	
	tests := []struct {
		name      string
		plaintext string
		want      bool
	}{
		{
			name:      "correct token",
			plaintext: token.GetPlainToken(),
			want:      true,
		},
		{
			name:      "incorrect token",
			plaintext: "wrong-token",
			want:      false,
		},
		{
			name:      "empty token",
			plaintext: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := token.ValidateHash(tt.plaintext)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestToken_UpdateLastUsed(t *testing.T) {
	token, err := NewRefreshToken("user-123", "test-session", []string{"user:read"})
	require.NoError(t, err)
	
	originalTime := token.LastUsedAt
	
	time.Sleep(10 * time.Millisecond) // 時間差を作る
	token.UpdateLastUsed()
	
	assert.True(t, token.LastUsedAt.After(originalTime))
	assert.WithinDuration(t, time.Now(), token.LastUsedAt, time.Second)
}