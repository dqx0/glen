package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// OAuth2Handler はAPI GatewayでのOAuth2フロー制御を担当
type OAuth2Handler struct {
	authServiceURL string
}

// NewOAuth2Handler は新しいOAuth2Handlerを作成
func NewOAuth2Handler(authServiceURL string) *OAuth2Handler {
	return &OAuth2Handler{
		authServiceURL: authServiceURL,
	}
}

// AuthorizeRequest はOAuth2認可リクエストの構造体
type AuthorizeRequest struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// HandleAuthorize はOAuth2認可エンドポイントを処理
func (h *OAuth2Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// パラメータを解析
	var req AuthorizeRequest
	if r.Method == http.MethodGet {
		req = h.parseAuthorizeParams(r.URL.Query())
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
			return
		}
		req = h.parseAuthorizeParams(r.Form)
	} else {
		h.writeError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// 基本的なバリデーション
	if req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	// ユーザー認証状態をチェック
	userID := h.getUserIDFromSession(r)
	if userID == "" {
		// 未認証の場合、ログインページにリダイレクト
		h.redirectToLogin(w, r, req)
		return
	}
	
	// GETリクエストで同意パラメータがある場合の処理
	if r.Method == http.MethodGet && r.URL.Query().Get("consent") != "" {
		consent := r.URL.Query().Get("consent")
		if consent == "approve" {
			h.processAuthorization(w, r, userID, req)
			return
		}
		if consent == "deny" {
			h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "User denied authorization")
			return
		}
	}

	// POST の場合（フロントエンドからの同意結果）
	if r.Method == http.MethodPost {
		// フロントエンドからのPOSTの場合、Authorizationヘッダーからユーザー認証
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if frontendUserID := h.extractUserIDFromJWT(token); frontendUserID != "" {
				userID = frontendUserID
				log.Printf("OAuth2 Gateway: Using user ID from Authorization header: %s", userID)
			}
		}
		
		if r.FormValue("consent") == "approve" {
			h.processAuthorization(w, r, userID, req)
			return
		}
		
		if r.FormValue("consent") == "deny" {
			// 図に従って、拒否時は最初からやり直し（サンプルアプリに戻る）
			h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "User denied authorization")
			return
		}
	}

	// GETまたは認証済みの場合、フロントエンドの同意画面にリダイレクト
	h.redirectToConsentScreen(w, r, req, userID)
}

// parseAuthorizeParams はURLパラメータまたはフォームデータからAuthorizeRequestを構築
func (h *OAuth2Handler) parseAuthorizeParams(values url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ClientID:            values.Get("client_id"),
		RedirectURI:         values.Get("redirect_uri"),
		ResponseType:        values.Get("response_type"),
		Scope:               values.Get("scope"),
		State:               values.Get("state"),
		CodeChallenge:       values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
	}
}

// getUserIDFromSession はセッション、Authorizationヘッダー、またはクエリパラメータからユーザーIDを取得
func (h *OAuth2Handler) getUserIDFromSession(r *http.Request) string {
	// まずクエリパラメータからauth_tokenをチェック（OAuth2ログイン後）
	authToken := r.URL.Query().Get("auth_token")
	if authToken != "" {
		log.Printf("OAuth2 Gateway: Found auth_token in query params: %s...", authToken[:20])
		
		// JWT トークンの場合は、デコードしてユーザーIDを取得する
		if userID := h.extractUserIDFromJWT(authToken); userID != "" {
			log.Printf("OAuth2 Gateway: Extracted user ID from JWT: %s", userID)
			return userID
		}
		
		// トークンからユーザーIDを抽出（簡単な形式: "session_user_username_username"）
		if strings.HasPrefix(authToken, "session_user_") {
			parts := strings.Split(authToken, "_")
			if len(parts) >= 3 {
				userID := "user_" + parts[2]
				log.Printf("OAuth2 Gateway: Extracted user ID from auth_token: %s", userID)
				return userID
			}
		}
	}

	// 次にAuthorizationヘッダーをチェック（OAuth2フロー用）
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		log.Printf("OAuth2 Gateway: Found Authorization header with token")
		
		// トークンからユーザーIDを抽出（簡単な形式: "session_user_username_username"）
		if strings.HasPrefix(token, "session_user_") {
			parts := strings.Split(token, "_")
			if len(parts) >= 3 {
				userID := "user_" + parts[2]
				log.Printf("OAuth2 Gateway: Extracted user ID from token: %s", userID)
				return userID
			}
		}
	}

	// 次にglen_sessionクッキーをチェック
	cookie, err := r.Cookie("glen_session")
	if err != nil {
		log.Printf("OAuth2 Gateway: No glen_session cookie found")
		return ""
	}

	// セッショントークンからユーザーIDを抽出
	// 簡単な形式: "session_user_username_username"
	if strings.HasPrefix(cookie.Value, "session_user_") {
		parts := strings.Split(cookie.Value, "_")
		if len(parts) >= 3 {
			userID := "user_" + parts[2]
			log.Printf("OAuth2 Gateway: Extracted user ID from cookie: %s", userID)
			return userID
		}
	}

	log.Printf("OAuth2 Gateway: Could not extract user ID from session or auth header")
	return ""
}

// redirectToLogin はログインページにリダイレクト
func (h *OAuth2Handler) redirectToLogin(w http.ResponseWriter, r *http.Request, req AuthorizeRequest) {
	// 現在のリクエストURLを構築
	returnURL := h.buildReturnURL(req)
	
	// フロントエンドのログインページのURLを正しく構築
	loginBaseURL, _ := url.Parse("http://localhost:5173/login")
	loginParams := url.Values{}
	loginParams.Set("redirect_uri", returnURL)
	loginBaseURL.RawQuery = loginParams.Encode()
	
	loginURL := loginBaseURL.String()
	log.Printf("OAuth2 Gateway: Redirecting to login: %s", loginURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// buildReturnURL は認証後の戻りURLを構築
func (h *OAuth2Handler) buildReturnURL(req AuthorizeRequest) string {
	baseURL := "http://localhost:8080/api/v1/oauth2/authorize"
	params := url.Values{}
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("response_type", req.ResponseType)
	params.Set("scope", req.Scope)
	if req.State != "" {
		params.Set("state", req.State)
	}
	if req.CodeChallenge != "" {
		params.Set("code_challenge", req.CodeChallenge)
		params.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	
	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

// processAuthorization は認可処理をAuth Serviceに委譲
func (h *OAuth2Handler) processAuthorization(w http.ResponseWriter, r *http.Request, userID string, req AuthorizeRequest) {
	// Auth Serviceの認可エンドポイントを呼び出し
	authURL := fmt.Sprintf("%s/api/v1/oauth2/authorize", h.authServiceURL)
	
	// リクエストボディを構築
	requestData := map[string]any{
		"user_id":                 userID,
		"client_id":              req.ClientID,
		"redirect_uri":           req.RedirectURI,
		"response_type":          req.ResponseType,
		"scope":                  req.Scope,
		"state":                  req.State,
		"code_challenge":         req.CodeChallenge,
		"code_challenge_method":  req.CodeChallengeMethod,
	}
	
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "server_error", "Failed to process authorization")
		return
	}
	
	// Auth Serviceにリクエストを送信
	resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("OAuth2 Gateway: Failed to call auth service: %v", err)
		h.writeError(w, http.StatusInternalServerError, "server_error", "Authorization service unavailable")
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		log.Printf("OAuth2 Gateway: Auth service returned error: %d", resp.StatusCode)
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "Authorization failed")
		return
	}
	
	// Auth Serviceからのレスポンスを解析
	var authResponse struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		log.Printf("OAuth2 Gateway: Failed to decode auth response: %v", err)
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "Invalid authorization response")
		return
	}
	
	// クライアントのコールバックURLにリダイレクト
	h.redirectWithCode(w, r, req.RedirectURI, authResponse.Code, authResponse.State)
}

// redirectToConsentScreen はフロントエンドの同意画面にリダイレクト
func (h *OAuth2Handler) redirectToConsentScreen(w http.ResponseWriter, r *http.Request, req AuthorizeRequest, userID string) {
	// フロントエンドの同意画面URLを構築
	consentBaseURL, _ := url.Parse("http://localhost:5173/oauth2/consent")
	consentParams := url.Values{}
	consentParams.Set("client_id", req.ClientID)
	consentParams.Set("redirect_uri", req.RedirectURI)
	consentParams.Set("response_type", req.ResponseType)
	consentParams.Set("scope", req.Scope)
	consentParams.Set("state", req.State)
	if req.CodeChallenge != "" {
		consentParams.Set("code_challenge", req.CodeChallenge)
		consentParams.Set("code_challenge_method", req.CodeChallengeMethod)
	}
	// ユーザーIDも渡す
	consentParams.Set("user_id", userID)
	
	consentBaseURL.RawQuery = consentParams.Encode()
	consentURL := consentBaseURL.String()
	
	log.Printf("OAuth2 Gateway: Redirecting to consent screen: %s", consentURL)
	http.Redirect(w, r, consentURL, http.StatusFound)
}

// redirectWithCode は認可コードと共にクライアントにリダイレクト
func (h *OAuth2Handler) redirectWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		log.Printf("OAuth2 Gateway: Invalid redirect URI: %v", err)
		return
	}

	query := u.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}

	u.RawQuery = query.Encode()
	finalURL := u.String()

	log.Printf("OAuth2 Gateway: Redirecting to client callback: %s", finalURL)
	http.Redirect(w, r, finalURL, http.StatusFound)
}

// redirectWithError はエラーと共にクライアントにリダイレクト
func (h *OAuth2Handler) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, errorDescription string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, errorCode, errorDescription)
		return
	}

	query := u.Query()
	query.Set("error", errorCode)
	if errorDescription != "" {
		query.Set("error_description", errorDescription)
	}
	if state != "" {
		query.Set("state", state)
	}

	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// writeError はJSONエラーレスポンスを書き込み
func (h *OAuth2Handler) writeError(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
	}
	
	json.NewEncoder(w).Encode(response)
}

// extractUserIDFromJWT はJWTトークンからユーザーIDを抽出（簡易版、署名検証なし）
func (h *OAuth2Handler) extractUserIDFromJWT(token string) string {
	// JWT形式: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		log.Printf("OAuth2 Gateway: Invalid JWT format")
		return ""
	}
	
	// ペイロード部分をデコード
	payload := parts[1]
	// Base64 URL デコード用にパディングを追加
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}
	
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("OAuth2 Gateway: Failed to decode JWT payload: %v", err)
		return ""
	}
	
	// JSONをパース
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		log.Printf("OAuth2 Gateway: Failed to parse JWT claims: %v", err)
		return ""
	}
	
	// user_idを取得
	if userID, ok := claims["user_id"].(string); ok {
		log.Printf("OAuth2 Gateway: Found user_id in JWT: %s", userID)
		return userID // そのまま返す（既に適切な形式になっている可能性）
	}
	
	log.Printf("OAuth2 Gateway: No user_id found in JWT claims")
	return ""
}