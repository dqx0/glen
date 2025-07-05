package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/dqx0/glen/social-service/internal/models"
)

func TestOAuth2Service_GetAuthURL(t *testing.T) {
	config := &models.OAuth2Config{
		ClientID:    "test-client-id",
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"openid", "email", "profile"},
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
	}
	
	service := NewOAuth2Service(config)
	
	tests := []struct {
		name  string
		state string
	}{
		{
			name:  "with state parameter",
			state: "random-state-123",
		},
		{
			name:  "with different state",
			state: "another-state-456",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := service.GetAuthURL(tt.state)
			
			assert.Contains(t, authURL, config.AuthURL)
			assert.Contains(t, authURL, "client_id="+config.ClientID)
			assert.Contains(t, authURL, "redirect_uri="+config.RedirectURL)
			assert.Contains(t, authURL, "state="+tt.state)
			assert.Contains(t, authURL, "response_type=code")
			assert.Contains(t, authURL, "scope=openid+email+profile")
		})
	}
}

func TestOAuth2Service_ExchangeCodeForToken(t *testing.T) {
	// モックOAuth2サーバーを作成
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && r.Method == "POST" {
			// リクエストの検証
			err := r.ParseForm()
			require.NoError(t, err)
			
			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "test-code", r.FormValue("code"))
			assert.Equal(t, "test-client-id", r.FormValue("client_id"))
			assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))
			assert.Equal(t, "http://localhost:8080/callback", r.FormValue("redirect_uri"))
			
			// レスポンスを返す
			response := map[string]interface{}{
				"access_token":  "access-token-123",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-token-456",
				"scope":         "openid email profile",
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()
	
	config := &models.OAuth2Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/callback",
		TokenURL:     mockServer.URL + "/token",
	}
	
	service := NewOAuth2Service(config)
	
	t.Run("successful token exchange", func(t *testing.T) {
		token, err := service.ExchangeCodeForToken(context.Background(), "test-code")
		
		require.NoError(t, err)
		require.NotNil(t, token)
		
		assert.Equal(t, "access-token-123", token.AccessToken)
		assert.Equal(t, "Bearer", token.TokenType)
		assert.Equal(t, "refresh-token-456", token.RefreshToken)
		assert.Equal(t, 3600, token.ExpiresIn)
	})
	
	t.Run("invalid authorization code", func(t *testing.T) {
		token, err := service.ExchangeCodeForToken(context.Background(), "")
		
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Equal(t, ErrInvalidAuthCode, err)
	})
}

func TestOAuth2Service_GetUserInfo(t *testing.T) {
	// モックAPIサーバーを作成
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/userinfo" && r.Method == "GET" {
			// Authorizationヘッダーの検証
			authHeader := r.Header.Get("Authorization")
			assert.Equal(t, "Bearer access-token-123", authHeader)
			
			// ユーザー情報のレスポンス
			userInfo := map[string]interface{}{
				"id":            "google-user-123",
				"email":         "user@gmail.com",
				"name":          "Test User",
				"picture":       "https://lh3.googleusercontent.com/photo.jpg",
				"verified_email": true,
				"locale":        "en",
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(userInfo)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()
	
	config := &models.OAuth2Config{
		UserInfoURL: mockServer.URL + "/userinfo",
	}
	
	service := NewOAuth2Service(config)
	
	t.Run("successful user info retrieval", func(t *testing.T) {
		token := &OAuth2Token{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
		}
		
		userInfo, err := service.GetUserInfo(context.Background(), token)
		
		require.NoError(t, err)
		require.NotNil(t, userInfo)
		
		assert.Equal(t, "google-user-123", userInfo["id"])
		assert.Equal(t, "user@gmail.com", userInfo["email"])
		assert.Equal(t, "Test User", userInfo["name"])
		assert.Equal(t, "https://lh3.googleusercontent.com/photo.jpg", userInfo["picture"])
		assert.Equal(t, true, userInfo["verified_email"])
	})
	
	t.Run("invalid access token", func(t *testing.T) {
		userInfo, err := service.GetUserInfo(context.Background(), nil)
		
		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Equal(t, ErrInvalidToken, err)
	})
	
	t.Run("empty access token", func(t *testing.T) {
		token := &OAuth2Token{
			AccessToken: "",
			TokenType:   "Bearer",
		}
		
		userInfo, err := service.GetUserInfo(context.Background(), token)
		
		assert.Error(t, err)
		assert.Nil(t, userInfo)
		assert.Equal(t, ErrInvalidToken, err)
	})
}

func TestOAuth2Service_ValidateState(t *testing.T) {
	config := &models.OAuth2Config{}
	service := NewOAuth2Service(config)
	
	tests := []struct {
		name           string
		providedState  string
		expectedState  string
		wantValid      bool
	}{
		{
			name:          "valid state",
			providedState: "valid-state-123",
			expectedState: "valid-state-123",
			wantValid:     true,
		},
		{
			name:          "invalid state",
			providedState: "invalid-state",
			expectedState: "expected-state",
			wantValid:     false,
		},
		{
			name:          "empty provided state",
			providedState: "",
			expectedState: "expected-state",
			wantValid:     false,
		},
		{
			name:          "empty expected state",
			providedState: "provided-state",
			expectedState: "",
			wantValid:     false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := service.ValidateState(tt.providedState, tt.expectedState)
			assert.Equal(t, tt.wantValid, isValid)
		})
	}
}

func TestNewOAuth2Service(t *testing.T) {
	tests := []struct {
		name    string
		config  *models.OAuth2Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &models.OAuth2Config{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/callback",
				AuthURL:      "https://example.com/auth",
				TokenURL:     "https://example.com/token",
				UserInfoURL:  "https://example.com/userinfo",
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing client ID",
			config: &models.OAuth2Config{
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/callback",
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewOAuth2Service(tt.config)
			
			if tt.wantErr {
				assert.Nil(t, service)
			} else {
				assert.NotNil(t, service)
				assert.Equal(t, tt.config, service.config)
			}
		})
	}
}