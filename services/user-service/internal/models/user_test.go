package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_Create(t *testing.T) {
	tests := []struct {
		name     string
		username string
		email    string
		password string
		wantErr  bool
	}{
		{
			name:     "valid user with username only",
			username: "testuser",
			email:    "",
			password: "",
			wantErr:  false,
		},
		{
			name:     "valid user with email",
			username: "testuser",
			email:    "test@example.com",
			password: "",
			wantErr:  false,
		},
		{
			name:     "valid user with password",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "invalid - empty username",
			username: "",
			email:    "test@example.com",
			password: "password123",
			wantErr:  true,
		},
		{
			name:     "invalid - invalid email",
			username: "testuser",
			email:    "invalid-email",
			password: "password123",
			wantErr:  true,
		},
		{
			name:     "invalid - username too long",
			username: "a" + string(make([]byte, 50)),
			email:    "test@example.com",
			password: "password123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := NewUser(tt.username, tt.email, tt.password)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)
				
				assert.Equal(t, tt.username, user.Username)
				assert.Equal(t, tt.email, user.Email)
				assert.True(t, user.IsActive)
				assert.NotEmpty(t, user.ID)
				assert.False(t, user.CreatedAt.IsZero())
				assert.False(t, user.UpdatedAt.IsZero())
				
				// パスワードがある場合はハッシュ化されているかチェック
				if tt.password != "" {
					assert.NotEmpty(t, user.PasswordHash)
					assert.NotEqual(t, tt.password, user.PasswordHash)
				}
			}
		})
	}
}

func TestUser_ValidatePassword(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "correct password",
			password: "password123",
			want:     true,
		},
		{
			name:     "incorrect password",
			password: "wrongpassword",
			want:     false,
		},
		{
			name:     "empty password",
			password: "",
			want:     false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.ValidatePassword(tt.password)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestUser_UpdatePassword(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "oldpassword")
	require.NoError(t, err)
	
	oldHash := user.PasswordHash
	
	err = user.UpdatePassword("newpassword")
	require.NoError(t, err)
	
	assert.NotEqual(t, oldHash, user.PasswordHash)
	assert.True(t, user.ValidatePassword("newpassword"))
	assert.False(t, user.ValidatePassword("oldpassword"))
}

func TestUser_SetEmailVerified(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)
	
	assert.False(t, user.EmailVerified)
	
	user.SetEmailVerified(true)
	assert.True(t, user.EmailVerified)
}

func TestUser_IsActive(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)
	
	assert.True(t, user.IsActive)
	
	user.IsActive = false
	assert.False(t, user.IsActive)
}