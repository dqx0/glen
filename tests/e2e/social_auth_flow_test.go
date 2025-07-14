package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSocialAuthFlow tests the OAuth2 social authentication flow
func TestSocialAuthFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	apiGatewayURL := getEnvOrDefault("API_GATEWAY_URL", "http://localhost:8080")

	t.Run("Google OAuth2 authorization flow", func(t *testing.T) {
		// Step 1: Get authorization URL
		authURL := getAuthorizationURL(t, apiGatewayURL, "google")
		require.NotEmpty(t, authURL)
		assert.Contains(t, authURL, "accounts.google.com")
		assert.Contains(t, authURL, "client_id")
		assert.Contains(t, authURL, "redirect_uri")
		assert.Contains(t, authURL, "state")

		// Step 2: Simulate OAuth2 callback (in real scenario, user would be redirected)
		// For E2E testing, we would need mock OAuth2 providers or test credentials
		t.Log("Authorization URL generated:", authURL)
		
		// Note: Full OAuth2 flow testing requires either:
		// 1. Mock OAuth2 provider setup
		// 2. Test credentials from real providers
		// 3. Browser automation tools like Selenium
	})

	t.Run("GitHub OAuth2 authorization flow", func(t *testing.T) {
		authURL := getAuthorizationURL(t, apiGatewayURL, "github")
		require.NotEmpty(t, authURL)
		assert.Contains(t, authURL, "github.com")
	})

	t.Run("Discord OAuth2 authorization flow", func(t *testing.T) {
		authURL := getAuthorizationURL(t, apiGatewayURL, "discord")
		require.NotEmpty(t, authURL)
		assert.Contains(t, authURL, "discord.com")
	})
}

// TestSocialAccountLinking tests linking social accounts to existing users
func TestSocialAccountLinking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	apiGatewayURL := getEnvOrDefault("API_GATEWAY_URL", "http://localhost:8080")
	
	// Create a test user first
	testUser := TestUser{
		Username: fmt.Sprintf("linktest_%d", time.Now().Unix()),
		Email:    fmt.Sprintf("linktest_%d@example.com", time.Now().Unix()),
		Password: "testpassword123",
	}

	t.Run("link social account to existing user", func(t *testing.T) {
		// Step 1: Register regular user
		userID := registerUser(t, apiGatewayURL, testUser)
		require.NotEmpty(t, userID)

		// Step 2: Login to get JWT
		tokens := loginUser(t, apiGatewayURL, userID, testUser)
		require.NotEmpty(t, tokens.AccessToken)

		// Step 3: Get linked social accounts (should be empty initially)
		accounts := getLinkedSocialAccounts(t, apiGatewayURL, tokens.AccessToken, userID)
		assert.Empty(t, accounts)

		// Note: Actual linking would require completing OAuth2 flow
		// This is a placeholder for the complete flow
		t.Log("User created and ready for social account linking:", userID)
	})
}

// Helper types for social auth
type AuthURLRequest struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
}

type AuthURLResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

type CallbackRequest struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state"`
}

type SocialAccount struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	Provider   string                 `json:"provider"`
	ProviderID string                 `json:"provider_id"`
	Profile    map[string]interface{} `json:"profile"`
	CreatedAt  time.Time              `json:"created_at"`
}

// Helper functions for social auth
func getAuthorizationURL(t *testing.T, baseURL, provider string) string {
	url := fmt.Sprintf("%s/api/v1/social/authorize", baseURL)
	
	reqData := AuthURLRequest{
		Provider: provider,
		State:    fmt.Sprintf("test_state_%d", time.Now().Unix()),
	}
	
	reqBody, _ := json.Marshal(reqData)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Authorization URL request should succeed")

	var authResp AuthURLResponse
	err = json.NewDecoder(resp.Body).Decode(&authResp)
	require.NoError(t, err)

	return authResp.AuthURL
}

func simulateOAuth2Callback(t *testing.T, baseURL, provider, code, state string) LoginResponse {
	url := fmt.Sprintf("%s/api/v1/social/callback", baseURL)
	
	callbackData := CallbackRequest{
		Provider: provider,
		Code:     code,
		State:    state,
	}
	
	reqBody, _ := json.Marshal(callbackData)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "OAuth2 callback should succeed")

	var tokens LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	require.NoError(t, err)

	return tokens
}

func getLinkedSocialAccounts(t *testing.T, baseURL, token, userID string) []SocialAccount {
	url := fmt.Sprintf("%s/api/v1/social/accounts?user_id=%s", baseURL, userID)
	
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Log response details for debugging
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Logf("Social accounts response status: %d", resp.StatusCode)
	t.Logf("Social accounts response body: %s", string(body))

	require.Equal(t, http.StatusOK, resp.StatusCode, "Getting linked accounts should succeed")

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// Accounts are nested under "accounts" key
	accountsData, exists := result["accounts"].([]interface{})
	require.True(t, exists, "Response should contain accounts array")

	var accounts []SocialAccount
	for _, account := range accountsData {
		accountMap := account.(map[string]interface{})
		accounts = append(accounts, SocialAccount{
			ID:       accountMap["id"].(string),
			UserID:   accountMap["user_id"].(string),
			Provider: accountMap["provider"].(string),
		})
	}

	return accounts
}

func unlinkSocialAccount(t *testing.T, baseURL, token, accountID, userID string) {
	url := fmt.Sprintf("%s/api/v1/social/accounts/%s", baseURL, accountID)
	
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	
	// Add user_id as query parameter for authorization
	q := req.URL.Query()
	q.Add("user_id", userID)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Unlinking social account should succeed")
}