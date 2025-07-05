package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSocialAccount_NewSocialAccount(t *testing.T) {
	tests := []struct {
		name         string
		userID       string
		provider     string
		providerID   string
		email        string
		displayName  string
		profileData  map[string]interface{}
		wantErr      bool
	}{
		{
			name:        "valid Google account",
			userID:      "user-123",
			provider:    ProviderGoogle,
			providerID:  "google-user-456",
			email:       "user@gmail.com",
			displayName: "Test User",
			profileData: map[string]interface{}{
				"picture": "https://lh3.googleusercontent.com/photo.jpg",
				"locale":  "en",
			},
			wantErr: false,
		},
		{
			name:        "valid GitHub account",
			userID:      "user-123",
			provider:    ProviderGitHub,
			providerID:  "12345678",
			email:       "user@users.noreply.github.com",
			displayName: "testuser",
			profileData: map[string]interface{}{
				"avatar_url": "https://avatars.githubusercontent.com/u/12345678?v=4",
				"login":      "testuser",
				"html_url":   "https://github.com/testuser",
			},
			wantErr: false,
		},
		{
			name:        "valid Discord account",
			userID:      "user-123",
			provider:    ProviderDiscord,
			providerID:  "987654321098765432",
			email:       "user@example.com",
			displayName: "TestUser#1234",
			profileData: map[string]interface{}{
				"avatar":        "a1b2c3d4e5f6g7h8i9j0",
				"discriminator": "1234",
				"username":      "TestUser",
			},
			wantErr: false,
		},
		{
			name:        "invalid - empty user ID",
			userID:      "",
			provider:    ProviderGoogle,
			providerID:  "google-user-456",
			email:       "user@gmail.com",
			displayName: "Test User",
			profileData: map[string]interface{}{},
			wantErr:     true,
		},
		{
			name:        "invalid - unsupported provider",
			userID:      "user-123",
			provider:    "twitter",
			providerID:  "twitter-user-789",
			email:       "user@twitter.com",
			displayName: "Test User",
			profileData: map[string]interface{}{},
			wantErr:     true,
		},
		{
			name:        "invalid - empty provider ID",
			userID:      "user-123",
			provider:    ProviderGoogle,
			providerID:  "",
			email:       "user@gmail.com",
			displayName: "Test User",
			profileData: map[string]interface{}{},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, err := NewSocialAccount(tt.userID, tt.provider, tt.providerID, tt.email, tt.displayName, tt.profileData)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, account)
			} else {
				require.NoError(t, err)
				require.NotNil(t, account)
				
				assert.Equal(t, tt.userID, account.UserID)
				assert.Equal(t, tt.provider, account.Provider)
				assert.Equal(t, tt.providerID, account.ProviderID)
				assert.Equal(t, tt.email, account.Email)
				assert.Equal(t, tt.displayName, account.DisplayName)
				assert.Equal(t, tt.profileData, account.ProfileData)
				assert.NotEmpty(t, account.ID)
				assert.False(t, account.CreatedAt.IsZero())
				assert.False(t, account.UpdatedAt.IsZero())
			}
		})
	}
}

func TestSocialAccount_UpdateProfile(t *testing.T) {
	account, err := NewSocialAccount(
		"user-123",
		ProviderGoogle,
		"google-user-456",
		"user@gmail.com",
		"Test User",
		map[string]interface{}{
			"picture": "https://old-picture.jpg",
		},
	)
	require.NoError(t, err)
	
	originalUpdatedAt := account.UpdatedAt
	time.Sleep(10 * time.Millisecond) // 時間差を作る
	
	newEmail := "newemail@gmail.com"
	newDisplayName := "Updated User"
	newProfileData := map[string]interface{}{
		"picture": "https://new-picture.jpg",
		"locale":  "ja",
	}
	
	account.UpdateProfile(newEmail, newDisplayName, newProfileData)
	
	assert.Equal(t, newEmail, account.Email)
	assert.Equal(t, newDisplayName, account.DisplayName)
	assert.Equal(t, newProfileData, account.ProfileData)
	assert.True(t, account.UpdatedAt.After(originalUpdatedAt))
}

func TestSocialAccount_IsLinkedToUser(t *testing.T) {
	account, err := NewSocialAccount(
		"user-123",
		ProviderGoogle,
		"google-user-456",
		"user@gmail.com",
		"Test User",
		map[string]interface{}{},
	)
	require.NoError(t, err)
	
	tests := []struct {
		name   string
		userID string
		want   bool
	}{
		{
			name:   "same user ID",
			userID: "user-123",
			want:   true,
		},
		{
			name:   "different user ID",
			userID: "user-456",
			want:   false,
		},
		{
			name:   "empty user ID",
			userID: "",
			want:   false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := account.IsLinkedToUser(tt.userID)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestSocialAccount_GetProfileValue(t *testing.T) {
	profileData := map[string]interface{}{
		"picture":   "https://picture.jpg",
		"locale":    "en",
		"verified":  true,
		"followers": 100,
	}
	
	account, err := NewSocialAccount(
		"user-123",
		ProviderGoogle,
		"google-user-456",
		"user@gmail.com",
		"Test User",
		profileData,
	)
	require.NoError(t, err)
	
	tests := []struct {
		name         string
		key          string
		wantExists   bool
		wantValue    interface{}
	}{
		{
			name:       "existing string value",
			key:        "picture",
			wantExists: true,
			wantValue:  "https://picture.jpg",
		},
		{
			name:       "existing bool value",
			key:        "verified",
			wantExists: true,
			wantValue:  true,
		},
		{
			name:       "existing int value",
			key:        "followers",
			wantExists: true,
			wantValue:  100,
		},
		{
			name:       "non-existent key",
			key:        "nonexistent",
			wantExists: false,
			wantValue:  nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, exists := account.GetProfileValue(tt.key)
			assert.Equal(t, tt.wantExists, exists)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

func TestSocialAccount_Providers(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		valid    bool
	}{
		{"Google provider", ProviderGoogle, true},
		{"GitHub provider", ProviderGitHub, true},
		{"Discord provider", ProviderDiscord, true},
		{"Invalid provider", "facebook", false},
		{"Empty provider", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := IsValidProvider(tt.provider)
			assert.Equal(t, tt.valid, isValid)
		})
	}
}