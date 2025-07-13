package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/auth-service/internal/oauth2/models"
)

// Mock repository for testing
type mockOAuth2Repository struct {
	clients         map[string]*models.OAuth2Client
	authCodes       map[string]*models.AuthorizationCode
	accessTokens    map[string]*models.OAuth2AccessToken
	refreshTokens   map[string]*models.OAuth2RefreshToken
	usedAuthCodes   map[string]bool
}

func newMockOAuth2Repository() *mockOAuth2Repository {
	return &mockOAuth2Repository{
		clients:       make(map[string]*models.OAuth2Client),
		authCodes:     make(map[string]*models.AuthorizationCode),
		accessTokens:  make(map[string]*models.OAuth2AccessToken),
		refreshTokens: make(map[string]*models.OAuth2RefreshToken),
		usedAuthCodes: make(map[string]bool),
	}
}

// Implement repository interface methods

func (m *mockOAuth2Repository) CreateClient(ctx context.Context, client *models.OAuth2Client) error {
	m.clients[client.ClientID] = client
	return nil
}

func (m *mockOAuth2Repository) GetClientByClientID(ctx context.Context, clientID string) (*models.OAuth2Client, error) {
	if client, exists := m.clients[clientID]; exists {
		return client, nil
	}
	return nil, ErrClientNotFound
}

func (m *mockOAuth2Repository) GetClientByID(ctx context.Context, id string) (*models.OAuth2Client, error) {
	for _, client := range m.clients {
		if client.ID == id {
			return client, nil
		}
	}
	return nil, ErrClientNotFound
}

func (m *mockOAuth2Repository) GetClientsByUserID(ctx context.Context, userID string) ([]*models.OAuth2Client, error) {
	var clients []*models.OAuth2Client
	for _, client := range m.clients {
		if client.UserID == userID {
			clients = append(clients, client)
		}
	}
	return clients, nil
}

func (m *mockOAuth2Repository) DeleteClient(ctx context.Context, clientID, userID string) error {
	if client, exists := m.clients[clientID]; exists && client.UserID == userID {
		delete(m.clients, clientID)
		return nil
	}
	return ErrClientNotFound
}

func (m *mockOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	m.authCodes[code.CodeHash] = code
	return nil
}

func (m *mockOAuth2Repository) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*models.AuthorizationCode, error) {
	if code, exists := m.authCodes[codeHash]; exists {
		// Create a copy to avoid modifying the original
		codeCopy := *code
		if m.usedAuthCodes[codeHash] {
			now := time.Now()
			codeCopy.UsedAt = &now
		}
		return &codeCopy, nil
	}
	return nil, ErrCodeNotFound
}

func (m *mockOAuth2Repository) MarkAuthorizationCodeAsUsed(ctx context.Context, codeHash string) error {
	m.usedAuthCodes[codeHash] = true
	return nil
}

func (m *mockOAuth2Repository) CreateAccessToken(ctx context.Context, token *models.OAuth2AccessToken) error {
	m.accessTokens[token.TokenHash] = token
	return nil
}

func (m *mockOAuth2Repository) GetAccessTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2AccessToken, error) {
	if token, exists := m.accessTokens[tokenHash]; exists {
		return token, nil
	}
	return nil, ErrTokenNotFound
}

func (m *mockOAuth2Repository) UpdateAccessTokenLastUsed(ctx context.Context, tokenHash string) error {
	if token, exists := m.accessTokens[tokenHash]; exists {
		token.LastUsedAt = time.Now()
	}
	return nil
}

func (m *mockOAuth2Repository) RevokeAccessToken(ctx context.Context, tokenHash string) error {
	if token, exists := m.accessTokens[tokenHash]; exists {
		now := time.Now()
		token.RevokedAt = &now
	}
	return nil
}

func (m *mockOAuth2Repository) CreateRefreshToken(ctx context.Context, token *models.OAuth2RefreshToken) error {
	m.refreshTokens[token.TokenHash] = token
	return nil
}

func (m *mockOAuth2Repository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2RefreshToken, error) {
	if token, exists := m.refreshTokens[tokenHash]; exists {
		return token, nil
	}
	return nil, ErrTokenNotFound
}

func (m *mockOAuth2Repository) UpdateRefreshTokenLastUsed(ctx context.Context, tokenHash string) error {
	if token, exists := m.refreshTokens[tokenHash]; exists {
		token.LastUsedAt = time.Now()
	}
	return nil
}

func (m *mockOAuth2Repository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	if token, exists := m.refreshTokens[tokenHash]; exists {
		now := time.Now()
		token.RevokedAt = &now
	}
	return nil
}

func (m *mockOAuth2Repository) RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error {
	now := time.Now()
	for _, token := range m.refreshTokens {
		if token.AccessTokenID == accessTokenID {
			token.RevokedAt = &now
		}
	}
	return nil
}

// Cleanup methods (not needed for tests)
func (m *mockOAuth2Repository) CleanupExpiredAuthorizationCodes(ctx context.Context) (int64, error) { return 0, nil }
func (m *mockOAuth2Repository) CleanupExpiredAccessTokens(ctx context.Context) (int64, error) { return 0, nil }
func (m *mockOAuth2Repository) CleanupExpiredRefreshTokens(ctx context.Context) (int64, error) { return 0, nil }

// Test setup helper
func setupOAuth2ServiceTest() (*OAuth2Service, *mockOAuth2Repository) {
	repo := newMockOAuth2Repository()
	service := NewOAuth2Service(repo)
	return service, repo
}

func TestOAuth2Service_CreateClient(t *testing.T) {
	service, _ := setupOAuth2ServiceTest()
	
	t.Run("successful client creation (confidential)", func(t *testing.T) {
		client, err := service.CreateClient(
			context.Background(),
			"user-123",
			"Test App",
			"Test application",
			[]string{"http://localhost:3000/callback"},
			[]string{"read", "write"},
			false, // confidential
		)
		
		require.NoError(t, err)
		assert.Equal(t, "user-123", client.UserID)
		assert.Equal(t, "Test App", client.Name)
		assert.False(t, client.IsPublic)
		assert.NotEmpty(t, client.ClientID)
		assert.NotEmpty(t, client.GetPlainClientSecret())
	})
	
	t.Run("successful client creation (public)", func(t *testing.T) {
		client, err := service.CreateClient(
			context.Background(),
			"user-123",
			"Public App",
			"Public application",
			[]string{"http://localhost:3000/callback"},
			[]string{"read"},
			true, // public
		)
		
		require.NoError(t, err)
		assert.True(t, client.IsPublic)
		assert.NotEmpty(t, client.ClientID)
	})
}

func TestOAuth2Service_ValidateClient(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test clients
	confidentialClient, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), confidentialClient)
	
	publicClient, _ := models.NewOAuth2Client(
		"user-123", "Public App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read"}, true,
	)
	repo.CreateClient(context.Background(), publicClient)
	
	t.Run("valid confidential client", func(t *testing.T) {
		client, err := service.ValidateClient(
			context.Background(),
			confidentialClient.ClientID,
			confidentialClient.GetPlainClientSecret(),
		)
		
		require.NoError(t, err)
		assert.Equal(t, confidentialClient.ClientID, client.ClientID)
	})
	
	t.Run("valid public client", func(t *testing.T) {
		client, err := service.ValidateClient(
			context.Background(),
			publicClient.ClientID,
			"", // no secret for public clients
		)
		
		require.NoError(t, err)
		assert.Equal(t, publicClient.ClientID, client.ClientID)
	})
	
	t.Run("invalid client ID", func(t *testing.T) {
		_, err := service.ValidateClient(
			context.Background(),
			"invalid-client-id",
			"secret",
		)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidClient, err)
	})
	
	t.Run("invalid client secret", func(t *testing.T) {
		_, err := service.ValidateClient(
			context.Background(),
			confidentialClient.ClientID,
			"wrong-secret",
		)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidClientSecret, err)
	})
}

func TestOAuth2Service_Authorize(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test client
	client, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), client)
	
	t.Run("successful authorization", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     client.ClientID,
			RedirectURI:  "http://localhost:3000/callback",
			ResponseType: "code",
			Scope:        "read write",
			State:        "test-state",
		}
		
		resp, err := service.Authorize(context.Background(), "user-456", req)
		
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Code)
		assert.Equal(t, "test-state", resp.State)
	})
	
	t.Run("invalid client", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "invalid-client",
			RedirectURI:  "http://localhost:3000/callback",
			ResponseType: "code",
			Scope:        "read",
		}
		
		_, err := service.Authorize(context.Background(), "user-456", req)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidClient, err)
	})
	
	t.Run("invalid redirect URI", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     client.ClientID,
			RedirectURI:  "http://evil.com/callback",
			ResponseType: "code",
			Scope:        "read",
		}
		
		_, err := service.Authorize(context.Background(), "user-456", req)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidRedirectURI, err)
	})
	
	t.Run("invalid scope", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     client.ClientID,
			RedirectURI:  "http://localhost:3000/callback",
			ResponseType: "code",
			Scope:        "admin delete", // not allowed scopes
		}
		
		_, err := service.Authorize(context.Background(), "user-456", req)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidScope, err)
	})
}

func TestOAuth2Service_Token_AuthorizationCode(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test client
	client, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), client)
	
	// Create authorization code
	authReq := &AuthorizeRequest{
		ClientID:     client.ClientID,
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: "code",
		Scope:        "read write",
		State:        "test-state",
	}
	
	authResp, err := service.Authorize(context.Background(), "user-456", authReq)
	require.NoError(t, err)
	
	t.Run("successful token exchange", func(t *testing.T) {
		tokenReq := &TokenRequest{
			GrantType:    "authorization_code",
			Code:         authResp.Code,
			RedirectURI:  "http://localhost:3000/callback",
			ClientID:     client.ClientID,
			ClientSecret: client.GetPlainClientSecret(),
		}
		
		tokenResp, err := service.Token(context.Background(), tokenReq)
		
		require.NoError(t, err)
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.NotEmpty(t, tokenResp.RefreshToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.Greater(t, tokenResp.ExpiresIn, int64(0))
		assert.Equal(t, "read write", tokenResp.Scope)
	})
	
	t.Run("invalid authorization code", func(t *testing.T) {
		tokenReq := &TokenRequest{
			GrantType:    "authorization_code",
			Code:         "invalid-code",
			RedirectURI:  "http://localhost:3000/callback",
			ClientID:     client.ClientID,
			ClientSecret: client.GetPlainClientSecret(),
		}
		
		_, err := service.Token(context.Background(), tokenReq)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidGrant, err)
	})
	
	t.Run("code already used", func(t *testing.T) {
		// Create a new authorization code for this test
		freshAuthReq := &AuthorizeRequest{
			ClientID:     client.ClientID,
			RedirectURI:  "http://localhost:3000/callback",
			ResponseType: "code",
			Scope:        "read write",
			State:        "fresh-test-state",
		}
		
		freshAuthResp, err := service.Authorize(context.Background(), "user-456", freshAuthReq)
		require.NoError(t, err)
		
		// First use
		tokenReq := &TokenRequest{
			GrantType:    "authorization_code",
			Code:         freshAuthResp.Code,
			RedirectURI:  "http://localhost:3000/callback",
			ClientID:     client.ClientID,
			ClientSecret: client.GetPlainClientSecret(),
		}
		
		_, err = service.Token(context.Background(), tokenReq)
		require.NoError(t, err)
		
		// Second use (should fail)
		_, err = service.Token(context.Background(), tokenReq)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidGrant, err)
	})
}

func TestOAuth2Service_Token_RefreshToken(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test client
	client, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), client)
	
	// Get initial tokens
	authReq := &AuthorizeRequest{
		ClientID:     client.ClientID,
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: "code",
		Scope:        "read write",
		State:        "test-state",
	}
	
	authResp, err := service.Authorize(context.Background(), "user-456", authReq)
	require.NoError(t, err)
	
	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         authResp.Code,
		RedirectURI:  "http://localhost:3000/callback",
		ClientID:     client.ClientID,
		ClientSecret: client.GetPlainClientSecret(),
	}
	
	initialTokenResp, err := service.Token(context.Background(), tokenReq)
	require.NoError(t, err)
	
	t.Run("successful refresh", func(t *testing.T) {
		refreshReq := &TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: initialTokenResp.RefreshToken,
			ClientID:     client.ClientID,
			ClientSecret: client.GetPlainClientSecret(),
		}
		
		refreshResp, err := service.Token(context.Background(), refreshReq)
		
		require.NoError(t, err)
		assert.NotEmpty(t, refreshResp.AccessToken)
		assert.NotEqual(t, initialTokenResp.AccessToken, refreshResp.AccessToken)
		assert.Equal(t, "Bearer", refreshResp.TokenType)
		assert.Greater(t, refreshResp.ExpiresIn, int64(0))
	})
	
	t.Run("invalid refresh token", func(t *testing.T) {
		refreshReq := &TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: "invalid-refresh-token",
			ClientID:     client.ClientID,
			ClientSecret: client.GetPlainClientSecret(),
		}
		
		_, err := service.Token(context.Background(), refreshReq)
		
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidGrant, err)
	})
}

func TestOAuth2Service_ValidateAccessToken(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test client and get token
	client, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), client)
	
	authReq := &AuthorizeRequest{
		ClientID:     client.ClientID,
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: "code",
		Scope:        "read write",
	}
	
	authResp, err := service.Authorize(context.Background(), "user-456", authReq)
	require.NoError(t, err)
	
	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         authResp.Code,
		RedirectURI:  "http://localhost:3000/callback",
		ClientID:     client.ClientID,
		ClientSecret: client.GetPlainClientSecret(),
	}
	
	tokenResp, err := service.Token(context.Background(), tokenReq)
	require.NoError(t, err)
	
	t.Run("valid access token", func(t *testing.T) {
		token, err := service.ValidateAccessToken(context.Background(), tokenResp.AccessToken)
		
		require.NoError(t, err)
		assert.Equal(t, client.ClientID, token.ClientID)
		assert.Equal(t, "user-456", token.UserID)
		assert.Contains(t, token.Scopes, "read")
		assert.Contains(t, token.Scopes, "write")
	})
	
	t.Run("invalid access token", func(t *testing.T) {
		_, err := service.ValidateAccessToken(context.Background(), "invalid-token")
		
		assert.Error(t, err)
		assert.Equal(t, ErrTokenNotFound, err)
	})
}

func TestOAuth2Service_Revoke(t *testing.T) {
	service, repo := setupOAuth2ServiceTest()
	
	// Create test client and get tokens
	client, _ := models.NewOAuth2Client(
		"user-123", "Test App", "Description",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write"}, false,
	)
	repo.CreateClient(context.Background(), client)
	
	authReq := &AuthorizeRequest{
		ClientID:     client.ClientID,
		RedirectURI:  "http://localhost:3000/callback",
		ResponseType: "code",
		Scope:        "read write",
	}
	
	authResp, err := service.Authorize(context.Background(), "user-456", authReq)
	require.NoError(t, err)
	
	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         authResp.Code,
		RedirectURI:  "http://localhost:3000/callback",
		ClientID:     client.ClientID,
		ClientSecret: client.GetPlainClientSecret(),
	}
	
	tokenResp, err := service.Token(context.Background(), tokenReq)
	require.NoError(t, err)
	
	t.Run("successful token revocation", func(t *testing.T) {
		err := service.Revoke(
			context.Background(),
			tokenResp.AccessToken,
			client.ClientID,
			client.GetPlainClientSecret(),
		)
		
		require.NoError(t, err)
		
		// Token should now be invalid
		_, err = service.ValidateAccessToken(context.Background(), tokenResp.AccessToken)
		assert.Error(t, err)
	})
	
	t.Run("revoke non-existent token", func(t *testing.T) {
		err := service.Revoke(
			context.Background(),
			"non-existent-token",
			client.ClientID,
			client.GetPlainClientSecret(),
		)
		
		// Should return error for non-existent token in our implementation
		assert.Error(t, err)
		assert.Equal(t, ErrTokenNotFound, err)
	})
}

func TestParseScopes(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single scope",
			input:    "read",
			expected: []string{"read"},
		},
		{
			name:     "multiple scopes",
			input:    "read write profile",
			expected: []string{"read", "write", "profile"},
		},
		{
			name:     "scopes with extra spaces",
			input:    "  read   write  profile  ",
			expected: []string{"read", "write", "profile"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseScopes(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHasAllScopes(t *testing.T) {
	available := []string{"read", "write", "profile"}
	
	testCases := []struct {
		name      string
		requested []string
		expected  bool
	}{
		{
			name:      "empty requested",
			requested: []string{},
			expected:  true,
		},
		{
			name:      "single scope present",
			requested: []string{"read"},
			expected:  true,
		},
		{
			name:      "multiple scopes present",
			requested: []string{"read", "write"},
			expected:  true,
		},
		{
			name:      "all scopes present",
			requested: []string{"read", "write", "profile"},
			expected:  true,
		},
		{
			name:      "scope not present",
			requested: []string{"admin"},
			expected:  false,
		},
		{
			name:      "some scopes not present",
			requested: []string{"read", "admin"},
			expected:  false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hasAllScopes(available, tc.requested)
			assert.Equal(t, tc.expected, result)
		})
	}
}