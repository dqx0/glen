package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserRegistrationAndAuth tests the complete user registration and authentication flow
func TestUserRegistrationAndAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	// Test configuration
	apiGatewayURL := getEnvOrDefault("API_GATEWAY_URL", "http://localhost:8080")
	testUser := TestUser{
		Username: fmt.Sprintf("testuser_%d", time.Now().Unix()),
		Email:    fmt.Sprintf("test_%d@example.com", time.Now().Unix()),
		Password: "testpassword123",
	}

	t.Run("complete user registration and authentication flow", func(t *testing.T) {
		// Step 1: Register user
		userID := registerUser(t, apiGatewayURL, testUser)
		require.NotEmpty(t, userID)

		// Step 2: Login and get JWT token
		tokens := loginUser(t, apiGatewayURL, testUser)
		require.NotEmpty(t, tokens.AccessToken)
		require.NotEmpty(t, tokens.RefreshToken)

		// Step 3: Access protected endpoint with JWT
		userInfo := getProtectedUserInfo(t, apiGatewayURL, tokens.AccessToken, testUser.Username)
		assert.Equal(t, testUser.Username, userInfo.Username)
		assert.Equal(t, testUser.Email, userInfo.Email)

		// Step 4: Create API Key
		apiKey := createAPIKey(t, apiGatewayURL, tokens.AccessToken, userID)
		require.NotEmpty(t, apiKey.Token)

		// Step 5: Access API with API Key
		userInfoWithAPIKey := getProtectedUserInfoWithAPIKey(t, apiGatewayURL, apiKey.Token, testUser.Username)
		assert.Equal(t, testUser.Username, userInfoWithAPIKey.Username)

		// Step 6: Refresh JWT token
		newTokens := refreshToken(t, apiGatewayURL, tokens.RefreshToken, testUser.Username)
		require.NotEmpty(t, newTokens.AccessToken)

		// Step 7: Revoke API Key
		revokeAPIKey(t, apiGatewayURL, tokens.AccessToken, apiKey.ID, userID)

		// Step 8: Verify API Key is revoked (should fail)
		verifyAPIKeyRevoked(t, apiGatewayURL, apiKey.Token, testUser.Username)
	})
}

// Helper types
type TestUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type UserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
}

type APIKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

// Helper functions
func registerUser(t *testing.T, baseURL string, user TestUser) string {
	url := fmt.Sprintf("%s/api/v1/users/register", baseURL)
	
	reqBody, _ := json.Marshal(user)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "User registration should succeed")

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	userID, exists := result["id"].(string)
	require.True(t, exists, "Response should contain user ID")
	
	return userID
}

func loginUser(t *testing.T, baseURL string, user TestUser) LoginResponse {
	url := fmt.Sprintf("%s/api/v1/auth/login", baseURL)
	
	loginReq := map[string]interface{}{
		"user_id":      "", // Will be filled by user service
		"username":     user.Username,
		"session_name": "e2e-test",
		"scopes":       []string{"user:read", "user:write"},
	}
	
	reqBody, _ := json.Marshal(loginReq)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")

	var tokens LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	require.NoError(t, err)

	return tokens
}

func getProtectedUserInfo(t *testing.T, baseURL, token, username string) UserInfo {
	url := fmt.Sprintf("%s/api/v1/users/%s", baseURL, username)
	
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Protected endpoint access should succeed")

	var userInfo UserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	require.NoError(t, err)

	return userInfo
}

func createAPIKey(t *testing.T, baseURL, token, userID string) APIKeyResponse {
	url := fmt.Sprintf("%s/api/v1/auth/api-keys", baseURL)
	
	createReq := map[string]interface{}{
		"user_id": userID,
		"name":    "e2e-test-api-key",
		"scopes":  []string{"api:read", "api:write"},
	}
	
	reqBody, _ := json.Marshal(createReq)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "API key creation should succeed")

	var apiKey APIKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&apiKey)
	require.NoError(t, err)

	return apiKey
}

func getProtectedUserInfoWithAPIKey(t *testing.T, baseURL, apiKey, username string) UserInfo {
	url := fmt.Sprintf("%s/api/v1/users/%s", baseURL, username)
	
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "API key access should succeed")

	var userInfo UserInfo
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	require.NoError(t, err)

	return userInfo
}

func refreshToken(t *testing.T, baseURL, refreshToken, username string) LoginResponse {
	url := fmt.Sprintf("%s/api/v1/auth/refresh", baseURL)
	
	refreshReq := map[string]interface{}{
		"refresh_token": refreshToken,
		"username":      username,
	}
	
	reqBody, _ := json.Marshal(refreshReq)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Token refresh should succeed")

	var tokens LoginResponse
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	require.NoError(t, err)

	return tokens
}

func revokeAPIKey(t *testing.T, baseURL, token, keyID, userID string) {
	url := fmt.Sprintf("%s/api/v1/auth/revoke", baseURL)
	
	revokeReq := map[string]interface{}{
		"token_id": keyID,
		"user_id":  userID,
	}
	
	reqBody, _ := json.Marshal(revokeReq)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "API key revocation should succeed")
}

func verifyAPIKeyRevoked(t *testing.T, baseURL, apiKey, username string) {
	url := fmt.Sprintf("%s/api/v1/users/%s", baseURL, username)
	
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Revoked API key should not work")
}

func getEnvOrDefault(key, defaultValue string) string {
	// In a real implementation, this would use os.Getenv
	return defaultValue
}