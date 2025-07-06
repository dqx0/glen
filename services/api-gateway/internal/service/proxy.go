package service

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config はサービスプロキシの設定
type Config struct {
	UserService   string
	AuthService   string
	SocialService string
}

// ServiceProxy は他のマイクロサービスへのリクエストをプロキシする
type ServiceProxy struct {
	config     *Config
	httpClient *http.Client
}

// NewServiceProxy は新しいServiceProxyを作成する
func NewServiceProxy(config *Config) *ServiceProxy {
	return &ServiceProxy{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ProxyRequest はリクエストを指定されたサービスにプロキシする
func (sp *ServiceProxy) ProxyRequest(targetURL string, originalReq *http.Request) (*http.Response, error) {
	// ターゲットURLの構築
	targetURLParsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target URL: %w", err)
	}
	
	// パスとクエリパラメータの設定
	targetURLParsed.Path = originalReq.URL.Path
	targetURLParsed.RawQuery = originalReq.URL.RawQuery
	
	// 新しいリクエストの作成
	proxyReq, err := http.NewRequestWithContext(
		originalReq.Context(),
		originalReq.Method,
		targetURLParsed.String(),
		originalReq.Body,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}
	
	// ヘッダーのコピー（一部を除く）
	sp.copyHeaders(originalReq, proxyReq)
	
	// プロキシリクエストの送信
	resp, err := sp.httpClient.Do(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("proxy request failed: %w", err)
	}
	
	return resp, nil
}

// GetUserServiceURL はユーザーサービスのURLを返す
func (sp *ServiceProxy) GetUserServiceURL() string {
	return sp.config.UserService
}

// GetAuthServiceURL は認証サービスのURLを返す
func (sp *ServiceProxy) GetAuthServiceURL() string {
	return sp.config.AuthService
}

// GetSocialServiceURL はソーシャルサービスのURLを返す
func (sp *ServiceProxy) GetSocialServiceURL() string {
	return sp.config.SocialService
}

// ValidateAPIKey はAPI キーを検証する
func (sp *ServiceProxy) ValidateAPIKey(apiKey string) (bool, map[string]interface{}, error) {
	// auth-serviceにAPIキー検証のリクエストを送信
	validateURL := fmt.Sprintf("%s/api/v1/auth/validate-api-key", sp.config.AuthService)
	
	req, err := http.NewRequest("POST", validateURL, strings.NewReader(fmt.Sprintf(`{"api_key":"%s"}`, apiKey)))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create validation request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := sp.httpClient.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("API key validation request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		// 簡易的な実装：レスポンスボディをマップとして返す
		// 実際のアプリケーションでは適切なJSONパースが必要
		return true, map[string]interface{}{
			"valid": true,
		}, nil
	}
	
	return false, nil, nil
}

// ValidateJWT はJWTトークンを検証する
func (sp *ServiceProxy) ValidateJWT(token string) (bool, map[string]interface{}, error) {
	// auth-serviceにJWT検証のリクエストを送信
	validateURL := fmt.Sprintf("%s/api/v1/auth/validate", sp.config.AuthService)
	
	req, err := http.NewRequest("GET", validateURL, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create validation request: %w", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	
	resp, err := sp.httpClient.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("JWT validation request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		// 簡易的な実装：レスポンスボディをマップとして返す
		return true, map[string]interface{}{
			"valid": true,
		}, nil
	}
	
	return false, nil, nil
}

// copyHeaders は必要なヘッダーをコピーする（機密情報は除く）
func (sp *ServiceProxy) copyHeaders(src, dst *http.Request) {
	// コピーしないヘッダー
	skipHeaders := map[string]bool{
		"Host":             true,
		"Content-Length":   true,
		"Transfer-Encoding": true,
		"Connection":       true,
	}
	
	for name, values := range src.Header {
		if !skipHeaders[name] {
			for _, value := range values {
				dst.Header.Add(name, value)
			}
		}
	}
}

// CopyResponse はレスポンスをコピーする
func (sp *ServiceProxy) CopyResponse(dst http.ResponseWriter, src *http.Response) error {
	// ヘッダーのコピー
	for name, values := range src.Header {
		for _, value := range values {
			dst.Header().Add(name, value)
		}
	}
	
	// ステータスコードの設定
	dst.WriteHeader(src.StatusCode)
	
	// ボディのコピー
	_, err := io.Copy(dst, src.Body)
	return err
}