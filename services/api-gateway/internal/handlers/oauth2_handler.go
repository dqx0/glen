package handlers

import (
	"bytes"
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

	// POST かつ consent=approve の場合、認可処理を実行
	if r.Method == http.MethodPost && r.FormValue("consent") == "approve" {
		h.processAuthorization(w, r, userID, req)
		return
	}

	// POST かつ consent=deny の場合、拒否処理
	if r.Method == http.MethodPost && r.FormValue("consent") == "deny" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "User denied authorization")
		return
	}

	// GETまたは認証済みの場合、同意画面を表示
	h.showConsentScreen(w, req, userID)
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

// getUserIDFromSession はセッションからユーザーIDを取得
func (h *OAuth2Handler) getUserIDFromSession(r *http.Request) string {
	// glen_sessionクッキーをチェック
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
			log.Printf("OAuth2 Gateway: Extracted user ID: %s", userID)
			return userID
		}
	}

	log.Printf("OAuth2 Gateway: Could not extract user ID from session")
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

// showConsentScreen は同意画面を表示
func (h *OAuth2Handler) showConsentScreen(w http.ResponseWriter, req AuthorizeRequest, userID string) {
	// シンプルな同意画面のHTML
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Glen OAuth2 - Authorization</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 100px auto; padding: 20px; background: #f5f5f5; }
        .consent-card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .title { text-align: center; margin-bottom: 30px; color: #333; }
        .app-info { background: #e3f2fd; padding: 20px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid #2196f3; }
        .permissions { margin: 20px 0; }
        .permission-item { padding: 10px 0; border-bottom: 1px solid #eee; }
        .permission-item:last-child { border-bottom: none; }
        .buttons { display: flex; gap: 10px; margin-top: 30px; }
        .btn { padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; flex: 1; }
        .btn-approve { background: #4caf50; color: white; }
        .btn-approve:hover { background: #45a049; }
        .btn-deny { background: #f44336; color: white; }
        .btn-deny:hover { background: #da190b; }
        .user-info { text-align: center; margin-bottom: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="consent-card">
        <h2 class="title">🔐 Glen OAuth2 Authorization</h2>
        
        <div class="user-info">
            Logged in as: <strong>%s</strong>
        </div>
        
        <div class="app-info">
            <h3>Authorization Request</h3>
            <p><strong>Application:</strong> %s</p>
            <p>This application is requesting access to your account.</p>
        </div>
        
        <div class="permissions">
            <h4>Requested Permissions:</h4>
            <div class="permission-item">
                <strong>%s</strong>
            </div>
        </div>
        
        <div class="buttons">
            <form method="POST" style="flex: 1;">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                <input type="hidden" name="consent" value="approve">
                <button type="submit" class="btn btn-approve">Allow</button>
            </form>
            
            <form method="POST" style="flex: 1;">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="consent" value="deny">
                <button type="submit" class="btn btn-deny">Deny</button>
            </form>
        </div>
    </div>
</body>
</html>`, userID, req.ClientID, req.Scope, 
		req.ClientID, req.RedirectURI, req.ResponseType, req.Scope, req.State, req.CodeChallenge, req.CodeChallengeMethod,
		req.ClientID, req.RedirectURI, req.State)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
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