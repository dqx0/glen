package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuth2Client(t *testing.T) {
	userID := "user-123"
	name := "Test Client"
	description := "Test client description"
	redirectURIs := []string{"http://localhost:3000/callback", "https://myapp.com/callback"}
	scopes := []string{"read", "write", "profile"}

	t.Run("successful client creation (confidential)", func(t *testing.T) {
		client, err := NewOAuth2Client(userID, name, description, redirectURIs, scopes, false)
		require.NoError(t, err)
		
		assert.Equal(t, userID, client.UserID)
		assert.Equal(t, name, client.Name)
		assert.Equal(t, description, client.Description)
		assert.Equal(t, redirectURIs, client.RedirectURIs)
		assert.Equal(t, scopes, client.Scopes)
		assert.False(t, client.IsPublic)
		assert.True(t, client.IsActive)
		assert.NotEmpty(t, client.ID)
		assert.NotEmpty(t, client.ClientID)
		assert.NotEmpty(t, client.ClientSecretHash)
		assert.NotEmpty(t, client.GetPlainClientSecret())
		assert.Equal(t, TokenEndpointAuthMethodClientSecretBasic, client.TokenEndpointAuthMethod)
		
		// Check grant types for confidential client
		assert.Contains(t, client.GrantTypes, GrantTypeAuthorizationCode)
		assert.Contains(t, client.GrantTypes, GrantTypeClientCredentials)
		assert.Contains(t, client.GrantTypes, GrantTypeRefreshToken)
		
		// Check response types
		assert.Contains(t, client.ResponseTypes, ResponseTypeCode)
	})

	t.Run("successful client creation (public/PKCE)", func(t *testing.T) {
		client, err := NewOAuth2Client(userID, name, description, redirectURIs, scopes, true)
		require.NoError(t, err)
		
		assert.True(t, client.IsPublic)
		assert.Equal(t, TokenEndpointAuthMethodNone, client.TokenEndpointAuthMethod)
		
		// Check grant types for public client
		assert.Contains(t, client.GrantTypes, GrantTypeAuthorizationCode)
		assert.NotContains(t, client.GrantTypes, GrantTypeClientCredentials)
		assert.Contains(t, client.GrantTypes, GrantTypeRefreshToken)
	})

	t.Run("validation errors", func(t *testing.T) {
		// Empty name
		_, err := NewOAuth2Client(userID, "", description, redirectURIs, scopes, false)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidClientName, err)
		
		// Empty redirect URIs
		_, err = NewOAuth2Client(userID, name, description, []string{}, scopes, false)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidRedirectURIs, err)
		
		// Invalid redirect URI
		_, err = NewOAuth2Client(userID, name, description, []string{"invalid-uri"}, scopes, false)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidRedirectURIs, err)
		
		// Empty scopes
		_, err = NewOAuth2Client(userID, name, description, redirectURIs, []string{}, false)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidScopes, err)
	})
}

func TestOAuth2Client_ValidateClientSecret(t *testing.T) {
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		[]string{"http://localhost:3000/callback"}, []string{"read"}, false)
	require.NoError(t, err)
	
	plainSecret := client.GetPlainClientSecret()
	
	t.Run("valid secret", func(t *testing.T) {
		assert.True(t, client.ValidateClientSecret(plainSecret))
	})
	
	t.Run("invalid secret", func(t *testing.T) {
		assert.False(t, client.ValidateClientSecret("wrong-secret"))
	})
	
	t.Run("empty secret", func(t *testing.T) {
		assert.False(t, client.ValidateClientSecret(""))
	})
}

func TestOAuth2Client_RedirectURIValidation(t *testing.T) {
	redirectURIs := []string{
		"http://localhost:3000/callback",
		"https://myapp.com/auth/callback",
	}
	
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		redirectURIs, []string{"read"}, false)
	require.NoError(t, err)
	
	t.Run("allowed redirect URIs", func(t *testing.T) {
		assert.True(t, client.IsRedirectURIAllowed("http://localhost:3000/callback"))
		assert.True(t, client.IsRedirectURIAllowed("https://myapp.com/auth/callback"))
	})
	
	t.Run("disallowed redirect URIs", func(t *testing.T) {
		assert.False(t, client.IsRedirectURIAllowed("http://evil.com/callback"))
		assert.False(t, client.IsRedirectURIAllowed("https://myapp.com/different/callback"))
	})
}

func TestOAuth2Client_ScopeValidation(t *testing.T) {
	scopes := []string{"read", "write", "profile"}
	
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		[]string{"http://localhost:3000/callback"}, scopes, false)
	require.NoError(t, err)
	
	t.Run("allowed individual scopes", func(t *testing.T) {
		assert.True(t, client.IsScopeAllowed("read"))
		assert.True(t, client.IsScopeAllowed("write"))
		assert.True(t, client.IsScopeAllowed("profile"))
	})
	
	t.Run("disallowed individual scopes", func(t *testing.T) {
		assert.False(t, client.IsScopeAllowed("admin"))
		assert.False(t, client.IsScopeAllowed("delete"))
	})
	
	t.Run("allowed scope combinations", func(t *testing.T) {
		assert.True(t, client.AreScopesAllowed([]string{"read"}))
		assert.True(t, client.AreScopesAllowed([]string{"read", "write"}))
		assert.True(t, client.AreScopesAllowed([]string{"read", "write", "profile"}))
	})
	
	t.Run("disallowed scope combinations", func(t *testing.T) {
		assert.False(t, client.AreScopesAllowed([]string{"read", "admin"}))
		assert.False(t, client.AreScopesAllowed([]string{"admin"}))
		assert.False(t, client.AreScopesAllowed([]string{"read", "write", "delete"}))
	})
}

func TestOAuth2Client_GrantTypeValidation(t *testing.T) {
	t.Run("confidential client", func(t *testing.T) {
		client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
			[]string{"http://localhost:3000/callback"}, []string{"read"}, false)
		require.NoError(t, err)
		
		assert.True(t, client.IsGrantTypeAllowed(GrantTypeAuthorizationCode))
		assert.True(t, client.IsGrantTypeAllowed(GrantTypeClientCredentials))
		assert.True(t, client.IsGrantTypeAllowed(GrantTypeRefreshToken))
	})
	
	t.Run("public client", func(t *testing.T) {
		client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
			[]string{"http://localhost:3000/callback"}, []string{"read"}, true)
		require.NoError(t, err)
		
		assert.True(t, client.IsGrantTypeAllowed(GrantTypeAuthorizationCode))
		assert.False(t, client.IsGrantTypeAllowed(GrantTypeClientCredentials))
		assert.True(t, client.IsGrantTypeAllowed(GrantTypeRefreshToken))
	})
}

func TestOAuth2Client_ResponseTypeValidation(t *testing.T) {
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		[]string{"http://localhost:3000/callback"}, []string{"read"}, false)
	require.NoError(t, err)
	
	assert.True(t, client.IsResponseTypeAllowed(ResponseTypeCode))
	assert.False(t, client.IsResponseTypeAllowed(ResponseTypeToken))
}

func TestOAuth2Client_SerializationDeserialization(t *testing.T) {
	redirectURIs := []string{"http://localhost:3000/callback", "https://myapp.com/callback"}
	scopes := []string{"read", "write", "profile"}
	
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		redirectURIs, scopes, false)
	require.NoError(t, err)
	
	// Serialization should already be done during creation
	assert.NotEmpty(t, client.RedirectURIsJSON)
	assert.NotEmpty(t, client.ScopesJSON)
	assert.NotEmpty(t, client.GrantTypesJSON)
	assert.NotEmpty(t, client.ResponseTypesJSON)
	
	// Test deserialization
	originalRedirectURIs := make([]string, len(client.RedirectURIs))
	copy(originalRedirectURIs, client.RedirectURIs)
	
	originalScopes := make([]string, len(client.Scopes))
	copy(originalScopes, client.Scopes)
	
	// Clear array fields
	client.RedirectURIs = nil
	client.Scopes = nil
	client.GrantTypes = nil
	client.ResponseTypes = nil
	
	// Deserialize
	err = client.DeserializeFromDB()
	require.NoError(t, err)
	
	// Verify arrays are restored
	assert.Equal(t, originalRedirectURIs, client.RedirectURIs)
	assert.Equal(t, originalScopes, client.Scopes)
	assert.NotEmpty(t, client.GrantTypes)
	assert.NotEmpty(t, client.ResponseTypes)
}

func TestOAuth2Client_UpdateClient(t *testing.T) {
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		[]string{"http://localhost:3000/callback"}, []string{"read"}, false)
	require.NoError(t, err)
	
	originalClientID := client.ClientID
	originalCreatedAt := client.CreatedAt
	
	newName := "Updated Client"
	newDescription := "Updated description"
	newRedirectURIs := []string{"https://newapp.com/callback"}
	newScopes := []string{"read", "write", "admin"}
	
	err = client.UpdateClient(newName, newDescription, newRedirectURIs, newScopes)
	require.NoError(t, err)
	
	// Verify updates
	assert.Equal(t, newName, client.Name)
	assert.Equal(t, newDescription, client.Description)
	assert.Equal(t, newRedirectURIs, client.RedirectURIs)
	assert.Equal(t, newScopes, client.Scopes)
	
	// Verify unchanged fields
	assert.Equal(t, originalClientID, client.ClientID)
	assert.Equal(t, originalCreatedAt, client.CreatedAt)
	assert.True(t, client.UpdatedAt.After(originalCreatedAt))
}

func TestOAuth2Client_ActivateDeactivate(t *testing.T) {
	client, err := NewOAuth2Client("user-123", "Test Client", "Description", 
		[]string{"http://localhost:3000/callback"}, []string{"read"}, false)
	require.NoError(t, err)
	
	// Initially active
	assert.True(t, client.IsActive)
	
	// Deactivate
	originalUpdatedAt := client.UpdatedAt
	client.Deactivate()
	assert.False(t, client.IsActive)
	assert.True(t, client.UpdatedAt.After(originalUpdatedAt))
	
	// Activate
	client.Activate()
	assert.True(t, client.IsActive)
}

func TestGenerateClientID(t *testing.T) {
	clientID := generateClientID()
	assert.NotEmpty(t, clientID)
	assert.Contains(t, clientID, "glen_client_")
	
	// Generate multiple IDs to ensure uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateClientID()
		assert.False(t, ids[id], "Client ID should be unique")
		ids[id] = true
	}
}

func TestGenerateClientSecretAndHash(t *testing.T) {
	secret1, hash1, err := generateClientSecretAndHash()
	require.NoError(t, err)
	assert.NotEmpty(t, secret1)
	assert.NotEmpty(t, hash1)
	
	secret2, hash2, err := generateClientSecretAndHash()
	require.NoError(t, err)
	assert.NotEmpty(t, secret2)
	assert.NotEmpty(t, hash2)
	
	// Ensure uniqueness
	assert.NotEqual(t, secret1, secret2)
	assert.NotEqual(t, hash1, hash2)
	
	// Verify hash validation
	client := &OAuth2Client{ClientSecretHash: hash1}
	assert.True(t, client.ValidateClientSecret(secret1))
	assert.False(t, client.ValidateClientSecret(secret2))
}

func TestSerializeDeserializeStringArray(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "empty array",
			input:    []string{},
			expected: "[]",
		},
		{
			name:     "single item",
			input:    []string{"item1"},
			expected: `["item1"]`,
		},
		{
			name:     "multiple items",
			input:    []string{"item1", "item2", "item3"},
			expected: `["item1","item2","item3"]`,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test serialization
			result, err := serializeStringArray(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
			
			// Test deserialization
			deserialized, err := deserializeStringArray(result)
			require.NoError(t, err)
			assert.Equal(t, tc.input, deserialized)
		})
	}
}