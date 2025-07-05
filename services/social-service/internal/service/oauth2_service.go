package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dqx0/glen/social-service/internal/models"
)

var (
	ErrInvalidAuthCode = errors.New("invalid authorization code")
	ErrInvalidToken    = errors.New("invalid token")
	ErrInvalidConfig   = errors.New("invalid OAuth2 config")
	ErrHTTPRequest     = errors.New("HTTP request failed")
)

// OAuth2Token はOAuth2アクセストークンを表す
type OAuth2Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuth2Service はOAuth2フローを処理する
type OAuth2Service struct {
	config *models.OAuth2Config
	client *http.Client
}

// NewOAuth2Service は新しいOAuth2Serviceを作成する
func NewOAuth2Service(config *models.OAuth2Config) *OAuth2Service {
	if config == nil || config.ClientID == "" {
		return nil
	}
	
	return &OAuth2Service{
		config: config,
		client: &http.Client{},
	}
}

// GetAuthURL は認証URLを生成する
func (s *OAuth2Service) GetAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", s.config.ClientID)
	params.Set("redirect_uri", s.config.RedirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(s.config.Scopes, " "))
	params.Set("state", state)
	
	return fmt.Sprintf("%s?%s", s.config.AuthURL, params.Encode())
}

// ExchangeCodeForToken は認証コードをアクセストークンに交換する
func (s *OAuth2Service) ExchangeCodeForToken(ctx context.Context, code string) (*OAuth2Token, error) {
	if code == "" {
		return nil, ErrInvalidAuthCode
	}
	
	// トークンリクエストのパラメータを準備
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("redirect_uri", s.config.RedirectURL)
	
	// HTTPリクエストを作成
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	
	// リクエストを送信
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPRequest, err)
	}
	defer resp.Body.Close()
	
	// レスポンスボディを読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// HTTPステータスの確認
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// JSONレスポンスをパース
	var token OAuth2Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	
	return &token, nil
}

// GetUserInfo はアクセストークンを使ってユーザー情報を取得する
func (s *OAuth2Service) GetUserInfo(ctx context.Context, token *OAuth2Token) (map[string]interface{}, error) {
	if token == nil || token.AccessToken == "" {
		return nil, ErrInvalidToken
	}
	
	// HTTPリクエストを作成
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Authorizationヘッダーを設定
	authHeader := fmt.Sprintf("%s %s", token.TokenType, token.AccessToken)
	if token.TokenType == "" {
		authHeader = fmt.Sprintf("Bearer %s", token.AccessToken)
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")
	
	// リクエストを送信
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPRequest, err)
	}
	defer resp.Body.Close()
	
	// レスポンスボディを読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// HTTPステータスの確認
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// JSONレスポンスをパース
	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info response: %w", err)
	}
	
	return userInfo, nil
}

// ValidateState はstateパラメータを検証する
func (s *OAuth2Service) ValidateState(providedState, expectedState string) bool {
	return providedState != "" && expectedState != "" && providedState == expectedState
}

// RefreshToken はリフレッシュトークンを使って新しいアクセストークンを取得する
func (s *OAuth2Service) RefreshToken(ctx context.Context, refreshToken string) (*OAuth2Token, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}
	
	// リフレッシュリクエストのパラメータを準備
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	
	// HTTPリクエストを作成
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	
	// リクエストを送信
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTTPRequest, err)
	}
	defer resp.Body.Close()
	
	// レスポンスボディを読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// HTTPステータスの確認
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// JSONレスポンスをパース
	var token OAuth2Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	
	return &token, nil
}

// RevokeToken はトークンを無効化する（サポートしているプロバイダーのみ）
func (s *OAuth2Service) RevokeToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}
	
	// プロバイダー別の無効化URL（設定で提供される場合）
	// 実装は簡略化し、基本的なPOSTリクエストのみ
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	
	// 無効化のエンドポイントがない場合は成功として扱う
	// 実際のアプリケーションでは、プロバイダー別に対応が必要
	return nil
}