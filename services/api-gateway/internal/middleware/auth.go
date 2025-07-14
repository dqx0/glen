package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPClient はHTTPリクエストを行うためのインターフェース
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthMiddleware は認証を処理するミドルウェア
type AuthMiddleware struct {
	authServiceURL string
	httpClient     HTTPClient
}

// NewAuthMiddleware は新しいAuthMiddlewareを作成する
func NewAuthMiddleware(authServiceURL string) *AuthMiddleware {
	return &AuthMiddleware{
		authServiceURL: authServiceURL,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

// NewAuthMiddlewareWithClient はカスタムHTTPクライアントを使用してAuthMiddlewareを作成する
func NewAuthMiddlewareWithClient(authServiceURL string, client HTTPClient) *AuthMiddleware {
	return &AuthMiddleware{
		authServiceURL: authServiceURL,
		httpClient:     client,
	}
}

// Handle は認証を確認してからハンドラーを実行する
func (a *AuthMiddleware) Handle(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authorizationヘッダーの確認
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "authorization header required")
			return
		}

		// Bearer token or API key の判定
		if strings.HasPrefix(authHeader, "Bearer ") {
			// JWT トークンの処理
			token := authHeader[7:] // "Bearer " を除去
			if !a.validateJWTToken(token) {
				a.writeUnauthorizedResponse(w, "invalid JWT token")
				return
			}
		} else if strings.HasPrefix(authHeader, "ApiKey ") {
			// API キーの処理
			apiKey := authHeader[7:] // "ApiKey " を除去
			if !a.validateAPIKey(apiKey) {
				a.writeUnauthorizedResponse(w, "invalid API key")
				return
			}

			// API KeyからユーザーIDを取得してヘッダーに設定
			if userID := a.extractUserIDFromAPIKey(apiKey); userID != "" {
				r.Header.Set("X-User-ID", userID)
			}
		} else {
			a.writeUnauthorizedResponse(w, "unsupported authorization type")
			return
		}

		// 認証成功 - コンテキストに認証情報を追加
		ctx := context.WithValue(r.Context(), "authenticated", true)
		r = r.WithContext(ctx)

		// ユーザーIDをヘッダーに設定（プロキシ用）
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := authHeader[7:]
			if userID := a.extractUserIDFromToken(token); userID != "" {
				r.Header.Set("X-User-ID", userID)
			}
		}

		// 次のハンドラーを実行
		handler(w, r)
	}
}

// validateJWTToken はJWTトークンまたはOAuth2アクセストークンを検証する
func (a *AuthMiddleware) validateJWTToken(token string) bool {
	if len(token) < 10 {
		return false
	}

	// トークンが適切な形式かチェック（JWT は通常 xxx.yyy.zzz の形式）
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		// JWTトークンの場合、auth-serviceに検証リクエストを送信
		return a.validateJWTWithAuthService(token)
	} else {
		// OAuth2 アクセストークンの可能性があるので introspection で検証
		log.Printf("Validating OAuth2 access token via introspection")
		return a.validateOAuth2Token(token)
	}
}

// JWTPayload はJWTのペイロード構造
type JWTPayload struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Exp      int64  `json:"exp"`
}

// extractUserIDFromToken はJWTトークンまたはOAuth2トークンからユーザーIDを抽出する
func (a *AuthMiddleware) extractUserIDFromToken(token string) string {
	// JWTかOAuth2トークンかを判定
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		// JWTトークンの場合
		return extractUserIDFromJWT(token)
	} else {
		// OAuth2トークンの場合、introspectionで取得
		return a.extractUserIDFromOAuth2Token(token)
	}
}

// extractUserIDFromJWT はJWTトークンからユーザーIDを抽出する
func extractUserIDFromJWT(token string) string {
	// JWTは3つの部分に分かれている: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("Invalid JWT format: expected 3 parts, got %d", len(parts))
		return ""
	}

	// ペイロード部分をデコード
	payload := parts[1]

	// Base64のパディングを修正
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Base64デコード
	payloadBytes, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("Failed to decode JWT payload: %v", err)
		return ""
	}

	// JSONをパース
	var jwtPayload JWTPayload
	if err := json.Unmarshal(payloadBytes, &jwtPayload); err != nil {
		log.Printf("Failed to parse JWT payload: %v", err)
		return ""
	}

	log.Printf("Extracted user_id from JWT: %s", jwtPayload.UserID)
	return jwtPayload.UserID
}

// validateOAuth2Token はOAuth2アクセストークンをintrospectionで検証する
func (a *AuthMiddleware) validateOAuth2Token(token string) bool {
	// OAuth2 introspection エンドポイントにリクエストを送信
	introspectURL := a.authServiceURL + "/api/v1/oauth2/introspect"

	// Form data for introspection request
	formData := url.Values{}
	formData.Set("token", token)

	req, err := http.NewRequest("POST", introspectURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		log.Printf("Failed to create introspection request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to call introspection endpoint: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Introspection endpoint returned status: %d", resp.StatusCode)
		return false
	}

	var introspectResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		log.Printf("Failed to decode introspection response: %v", err)
		return false
	}

	// Check if token is active
	active, ok := introspectResp["active"].(bool)
	if !ok || !active {
		log.Printf("OAuth2 token is not active")
		return false
	}

	log.Printf("OAuth2 token validation successful")
	return true
}

// extractUserIDFromOAuth2Token はOAuth2アクセストークンからユーザーIDを抽出する
func (a *AuthMiddleware) extractUserIDFromOAuth2Token(token string) string {
	// OAuth2 introspection エンドポイントにリクエストを送信
	introspectURL := a.authServiceURL + "/api/v1/oauth2/introspect"

	// Form data for introspection request
	formData := url.Values{}
	formData.Set("token", token)

	req, err := http.NewRequest("POST", introspectURL, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		log.Printf("Failed to create introspection request for user ID: %v", err)
		return ""
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to call introspection endpoint for user ID: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Introspection endpoint returned status for user ID: %d", resp.StatusCode)
		return ""
	}

	var introspectResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		log.Printf("Failed to decode introspection response for user ID: %v", err)
		return ""
	}

	// Check if token is active and extract username (which contains user ID)
	active, ok := introspectResp["active"].(bool)
	if !ok || !active {
		log.Printf("OAuth2 token is not active when extracting user ID")
		return ""
	}

	// Extract user ID from username field
	username, ok := introspectResp["username"].(string)
	if !ok {
		log.Printf("No username field in OAuth2 introspection response")
		return ""
	}

	log.Printf("Extracted user ID from OAuth2 token: %s", username)
	return username
}

// validateAPIKey はAPIキーを検証する
func (a *AuthMiddleware) validateAPIKey(apiKey string) bool {
	if len(apiKey) < 32 {
		return false
	}

	// Auth ServiceのAPIキー検証エンドポイントにリクエストを送信
	validateURL := a.authServiceURL + "/api/v1/auth/validate-api-key"

	// リクエストボディを構築
	requestData := map[string]string{
		"api_key": apiKey,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("Failed to marshal API key validation request: %v", err)
		return false
	}

	req, err := http.NewRequest("POST", validateURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create API key validation request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to call API key validation endpoint: %v", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// extractUserIDFromAPIKey はAPIキーからユーザーIDを抽出する
func (a *AuthMiddleware) extractUserIDFromAPIKey(apiKey string) string {
	// Auth Serviceの validate-api-key エンドポイントにリクエストを送信
	validateURL := a.authServiceURL + "/api/v1/auth/validate-api-key"

	// リクエストボディを構築
	requestData := map[string]string{
		"api_key": apiKey,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("Failed to marshal API key validation request: %v", err)
		return ""
	}

	req, err := http.NewRequest("POST", validateURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create API key validation request: %v", err)
		return ""
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to call API key validation endpoint: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("API key validation endpoint returned status: %d", resp.StatusCode)
		return ""
	}

	var validateResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		log.Printf("Failed to decode API key validation response: %v", err)
		return ""
	}

	// Check if API key is valid and extract user ID
	valid, ok := validateResp["valid"].(bool)
	if !ok || !valid {
		log.Printf("API key is not valid")
		return ""
	}

	userID, ok := validateResp["user_id"].(string)
	if !ok {
		log.Printf("No user_id field in API key validation response")
		return ""
	}

	log.Printf("Extracted user ID from API key: %s", userID)
	return userID
}

// writeUnauthorizedResponse は認証エラーレスポンスを書き込む
func (a *AuthMiddleware) writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := `{"success":false,"error":"` + message + `"}`
	w.Write([]byte(response))
}

// RequireAPIKey はAPIキー認証のみを要求するミドルウェア
func (a *AuthMiddleware) RequireAPIKey(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "API key required")
			return
		}

		if !strings.HasPrefix(authHeader, "ApiKey ") {
			a.writeUnauthorizedResponse(w, "API key format: 'ApiKey <your-key>'")
			return
		}

		apiKey := authHeader[7:]
		if !a.validateAPIKey(apiKey) {
			a.writeUnauthorizedResponse(w, "invalid API key")
			return
		}

		// 認証成功
		ctx := context.WithValue(r.Context(), "authenticated", true)
		ctx = context.WithValue(ctx, "auth_type", "api_key")
		r = r.WithContext(ctx)

		handler(w, r)
	}
}

// RequireJWT はJWT認証のみを要求するミドルウェア
func (a *AuthMiddleware) RequireJWT(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeUnauthorizedResponse(w, "JWT token required")
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.writeUnauthorizedResponse(w, "JWT format: 'Bearer <your-token>'")
			return
		}

		token := authHeader[7:]
		if !a.validateJWTToken(token) {
			a.writeUnauthorizedResponse(w, "invalid JWT token")
			return
		}

		// 認証成功
		ctx := context.WithValue(r.Context(), "authenticated", true)
		ctx = context.WithValue(ctx, "auth_type", "jwt")
		r = r.WithContext(ctx)

		handler(w, r)
	}
}

// validateJWTWithAuthService はAuth ServiceでJWTトークンを検証する
func (a *AuthMiddleware) validateJWTWithAuthService(token string) bool {
	// Auth ServiceのJWT検証エンドポイントにリクエストを送信
	validateURL := a.authServiceURL + "/api/v1/auth/validate-token"

	// リクエストボディを構築
	requestData := map[string]string{
		"token": token,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		log.Printf("Failed to marshal JWT validation request: %v", err)
		return false
	}

	req, err := http.NewRequest("POST", validateURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create JWT validation request: %v", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to call JWT validation endpoint: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("JWT validation endpoint returned status: %d", resp.StatusCode)
		return false
	}

	var validateResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		log.Printf("Failed to decode JWT validation response: %v", err)
		return false
	}

	// Check if JWT is valid
	valid, ok := validateResp["valid"].(bool)
	if !ok || !valid {
		log.Printf("JWT token is not valid")
		return false
	}

	log.Printf("JWT token validation successful")
	return true
}
