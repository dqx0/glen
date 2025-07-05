package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebAuthnCredential_Create(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "")
	require.NoError(t, err)
	
	tests := []struct {
		testName     string
		userID       string
		credentialID string
		publicKey    []byte
		deviceName   string
		transport    string
		wantErr      bool
	}{
		{
			testName:     "valid credential",
			userID:       user.ID,
			credentialID: "test-credential-id",
			publicKey:    []byte("mock-public-key"),
			deviceName:   "iPhone",
			transport:    "internal",
			wantErr:      false,
		},
		{
			testName:     "invalid - empty user ID",
			userID:       "",
			credentialID: "test-credential-id",
			publicKey:    []byte("mock-public-key"),
			deviceName:   "iPhone",
			transport:    "internal",
			wantErr:      true,
		},
		{
			testName:     "invalid - empty credential ID",
			userID:       user.ID,
			credentialID: "",
			publicKey:    []byte("mock-public-key"),
			deviceName:   "iPhone",
			transport:    "internal",
			wantErr:      true,
		},
		{
			testName:     "invalid - empty public key",
			userID:       user.ID,
			credentialID: "test-credential-id",
			publicKey:    []byte{},
			deviceName:   "iPhone",
			transport:    "internal",
			wantErr:      true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			credential, err := NewWebAuthnCredential(
				tt.userID,
				tt.credentialID,
				tt.publicKey,
				tt.deviceName,
				tt.transport,
			)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, credential)
			} else {
				require.NoError(t, err)
				require.NotNil(t, credential)
				
				assert.Equal(t, tt.userID, credential.UserID)
				assert.Equal(t, tt.credentialID, credential.CredentialID)
				assert.Equal(t, tt.publicKey, credential.PublicKey)
				assert.Equal(t, tt.deviceName, credential.Name)
				assert.Equal(t, tt.transport, credential.Transport)
				assert.Equal(t, int64(0), credential.Counter)
				assert.NotEmpty(t, credential.ID)
				assert.False(t, credential.CreatedAt.IsZero())
			}
		})
	}
}

func TestWebAuthnCredential_UpdateCounter(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "")
	require.NoError(t, err)
	
	credential, err := NewWebAuthnCredential(
		user.ID,
		"test-credential-id",
		[]byte("mock-public-key"),
		"iPhone",
		"internal",
	)
	require.NoError(t, err)
	
	assert.Equal(t, int64(0), credential.Counter)
	
	credential.UpdateCounter(5)
	assert.Equal(t, int64(5), credential.Counter)
	assert.False(t, credential.LastUsedAt.IsZero())
}

func TestWebAuthnCredential_IsValid(t *testing.T) {
	user, err := NewUser("testuser", "test@example.com", "")
	require.NoError(t, err)
	
	credential, err := NewWebAuthnCredential(
		user.ID,
		"test-credential-id",
		[]byte("mock-public-key"),
		"iPhone",
		"internal",
	)
	require.NoError(t, err)
	
	assert.True(t, credential.IsValid())
	
	// 空の認証情報は無効
	emptyCredential := &WebAuthnCredential{}
	assert.False(t, emptyCredential.IsValid())
}