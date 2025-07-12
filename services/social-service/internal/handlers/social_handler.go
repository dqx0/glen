package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dqx0/glen/social-service/internal/models"
	"github.com/dqx0/glen/social-service/internal/service"
)

// SocialAccountRepository はソーシャルアカウントの永続化を担当するインターフェース
type SocialAccountRepository interface {
	Create(ctx context.Context, account *models.SocialAccount) error
	GetByID(ctx context.Context, id string) (*models.SocialAccount, error)
	GetByUserID(ctx context.Context, userID string) ([]*models.SocialAccount, error)
	GetByProviderAndProviderID(ctx context.Context, provider, providerID string) (*models.SocialAccount, error)
	Update(ctx context.Context, account *models.SocialAccount) error
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// SocialHandler はソーシャルログイン関連のHTTPハンドラーを提供する
type SocialHandler struct {
	repo           SocialAccountRepository
	oauth2Configs  map[string]*models.OAuth2Config
	userServiceURL string
}

// NewSocialHandler は新しいSocialHandlerを作成する
func NewSocialHandler(repo SocialAccountRepository, oauth2Configs map[string]*models.OAuth2Config, userServiceURL string) *SocialHandler {
	return &SocialHandler{
		repo:           repo,
		oauth2Configs:  oauth2Configs,
		userServiceURL: userServiceURL,
	}
}

// AuthorizeRequest は認証開始のリクエスト
type AuthorizeRequest struct {
	Provider    string `json:"provider"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

// AuthorizeResponse は認証URLのレスポンス
type AuthorizeResponse struct {
	AuthURL  string `json:"auth_url"`
	Provider string `json:"provider"`
	State    string `json:"state"`
}

// CallbackRequest はOAuth2コールバックのリクエスト
type CallbackRequest struct {
	Provider    string `json:"provider"`
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

// CallbackResponse はコールバック処理のレスポンス
type CallbackResponse struct {
	SocialAccount *models.SocialAccount `json:"social_account"`
	IsNewAccount  bool                  `json:"is_new_account"`
}

// SocialLoginResponse はソーシャルログインのレスポンス
type SocialLoginResponse struct {
	UserID        string                `json:"user_id"`
	SocialAccount *models.SocialAccount `json:"social_account"`
	IsNewUser     bool                  `json:"is_new_user"`
}

// UserServiceResponse はuser-serviceからのレスポンス
type UserServiceResponse struct {
	Success bool        `json:"success"`
	User    interface{} `json:"user"`
	Error   string      `json:"error"`
}

// CreateUserRequest は新規ユーザー作成のリクエスト
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LinkAccountRequest はアカウント連携のリクエスト
type LinkAccountRequest struct {
	UserID   string `json:"user_id"`
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state"`
}

// GetAuthURL は認証URLを取得する
func (h *SocialHandler) GetAuthURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req AuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// プロバイダーの検証
	if !models.IsValidProvider(req.Provider) {
		writeErrorResponse(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	// OAuth2設定の取得
	config, exists := h.oauth2Configs[req.Provider]
	if !exists {
		writeErrorResponse(w, http.StatusBadRequest, "provider not configured")
		return
	}

	// リダイレクトURIの設定（リクエストから受け取った値を使用）
	if req.RedirectURI != "" {
		config.RedirectURL = req.RedirectURI
	}

	// OAuth2Serviceの作成
	oauth2Service := service.NewOAuth2Service(config)
	if oauth2Service == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "failed to create OAuth2 service")
		return
	}

	// 認証URLの生成
	authURL := oauth2Service.GetAuthURL(req.State)

	resp := AuthorizeResponse{
		AuthURL:  authURL,
		Provider: req.Provider,
		State:    req.State,
	}

	writeJSONResponse(w, http.StatusOK, resp)
}

// HandleSocialLogin はソーシャルログインのOAuth2コールバックを処理する
func (h *SocialHandler) HandleSocialLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// プロバイダーの検証
	if !models.IsValidProvider(req.Provider) {
		writeErrorResponse(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	// OAuth2設定の取得
	config, exists := h.oauth2Configs[req.Provider]
	if !exists {
		writeErrorResponse(w, http.StatusBadRequest, "provider not configured")
		return
	}

	// リダイレクトURIの設定（リクエストから受け取った値を使用）
	if req.RedirectURI != "" {
		config.RedirectURL = req.RedirectURI
	}

	// OAuth2Serviceの作成
	oauth2Service := service.NewOAuth2Service(config)
	if oauth2Service == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "failed to create OAuth2 service")
		return
	}

	// 認証コードをトークンに交換
	token, err := oauth2Service.ExchangeCodeForToken(r.Context(), req.Code)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to exchange code: %v", err))
		return
	}

	// ユーザー情報の取得
	userInfo, err := oauth2Service.GetUserInfo(r.Context(), token)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get user info: %v", err))
		return
	}

	fmt.Printf("DEBUG: UserInfo from Google: %+v\n", userInfo)

	// プロバイダーIDの抽出
	providerID, err := extractProviderID(req.Provider, userInfo)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to extract provider ID: %v", err))
		return
	}
	
	fmt.Printf("DEBUG: Provider ID extracted: %s\n", providerID)

	// 既存のソーシャルアカウントを確認
	existingAccount, err := h.repo.GetByProviderAndProviderID(r.Context(), req.Provider, providerID)
	if err != nil {
		// アカウントが見つからない場合は自動的にユーザーを作成または紐づけ
		userID, socialAccount, err := h.handleNewSocialLogin(r.Context(), req.Provider, providerID, userInfo)
		if err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to handle new social login: %v", err))
			return
		}
		
		email, _ := extractEmail(userInfo)
		fmt.Printf("DEBUG: New social login - userID: %s, email: %s\n", userID, email)
		resp := SocialLoginResponse{
			UserID:        userID,
			SocialAccount: socialAccount,
			IsNewUser:     true,
		}
		writeJSONResponse(w, http.StatusOK, resp)
		return
	}

	// 既存のアカウントを更新
	email, _ := extractEmail(userInfo)
	displayName, _ := extractDisplayName(req.Provider, userInfo)
	existingAccount.UpdateProfile(email, displayName, userInfo)

	if err := h.repo.Update(r.Context(), existingAccount); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to update social account: %v", err))
		return
	}

	fmt.Printf("DEBUG: Existing social login - userID: %s\n", existingAccount.UserID)
	resp := SocialLoginResponse{
		UserID:        existingAccount.UserID,
		SocialAccount: existingAccount,
		IsNewUser:     false,
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// HandleCallback はOAuth2コールバックを処理する（アカウント連携用）
func (h *SocialHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// プロバイダーの検証
	if !models.IsValidProvider(req.Provider) {
		writeErrorResponse(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	// OAuth2設定の取得
	config, exists := h.oauth2Configs[req.Provider]
	if !exists {
		writeErrorResponse(w, http.StatusBadRequest, "provider not configured")
		return
	}

	// リダイレクトURIの設定（リクエストから受け取った値を使用）
	if req.RedirectURI != "" {
		config.RedirectURL = req.RedirectURI
	}

	// OAuth2Serviceの作成
	oauth2Service := service.NewOAuth2Service(config)
	if oauth2Service == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "failed to create OAuth2 service")
		return
	}

	// 認証コードをトークンに交換
	token, err := oauth2Service.ExchangeCodeForToken(r.Context(), req.Code)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("failed to exchange code: %v", err))
		return
	}

	// ユーザー情報の取得
	userInfo, err := oauth2Service.GetUserInfo(r.Context(), token)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get user info: %v", err))
		return
	}

	// プロバイダーIDの抽出
	providerID, err := extractProviderID(req.Provider, userInfo)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to extract provider ID: %v", err))
		return
	}

	// 認証されたユーザーIDを取得（必須）
	userID := getUserIDFromContext(r)
	if userID == "" {
		writeErrorResponse(w, http.StatusUnauthorized, "user authentication required")
		return
	}

	// 既存のソーシャルアカウントを確認
	existingAccount, err := h.repo.GetByProviderAndProviderID(r.Context(), req.Provider, providerID)
	isNewAccount := err != nil

	if isNewAccount {

		// 新しいソーシャルアカウントを作成
		email, _ := extractEmail(userInfo)
		displayName, _ := extractDisplayName(req.Provider, userInfo)

		newAccount, err := models.NewSocialAccount(
			userID,
			req.Provider,
			providerID,
			email,
			displayName,
			userInfo,
		)
		if err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to create social account: %v", err))
			return
		}

		if err := h.repo.Create(r.Context(), newAccount); err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to save social account: %v", err))
			return
		}

		resp := CallbackResponse{
			SocialAccount: newAccount,
			IsNewAccount:  true,
		}
		writeJSONResponse(w, http.StatusCreated, resp)
	} else {
		// 既存のアカウントを更新
		email, _ := extractEmail(userInfo)
		displayName, _ := extractDisplayName(req.Provider, userInfo)
		existingAccount.UpdateProfile(email, displayName, userInfo)

		if err := h.repo.Update(r.Context(), existingAccount); err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to update social account: %v", err))
			return
		}

		resp := CallbackResponse{
			SocialAccount: existingAccount,
			IsNewAccount:  false,
		}
		writeJSONResponse(w, http.StatusOK, resp)
	}
}

// GetUserSocialAccounts はユーザーのソーシャルアカウント一覧を取得する
func (h *SocialHandler) GetUserSocialAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// ユーザーIDを取得（認証ミドルウェアまたはクエリパラメータから）
	userID := getUserIDFromContext(r)
	if userID == "" {
		// フォールバック：クエリパラメータから取得
		userID = r.URL.Query().Get("user_id")
		if userID == "" {
			writeErrorResponse(w, http.StatusBadRequest, "authentication required or user_id parameter required")
			return
		}
	}

	accounts, err := h.repo.GetByUserID(r.Context(), userID)
	if err != nil {
		// エラーの場合も空の配列を返してフロントエンドの処理を継続させる
		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"accounts": []interface{}{},
		})
		return
	}

	// アカウントがnilの場合の対応
	if accounts == nil {
		accounts = []*models.SocialAccount{}
	}

	// フロントエンドの期待する形式に合わせる
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"accounts": accounts,
	})
}

// getUserIDFromContext は認証ミドルウェアから設定されたユーザーIDを取得する
func getUserIDFromContext(r *http.Request) string {
	// 複数の方法でユーザーIDを取得を試みる
	
	// 1. コンテキストから取得（認証ミドルウェアが設定）
	if userID := r.Context().Value("user_id"); userID != nil {
		if uid, ok := userID.(string); ok && uid != "" {
			return uid
		}
	}
	
	// 2. ヘッダーから取得（API Gatewayが設定）
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	
	// 3. JWTトークンから取得（直接デコード）
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if userID := extractUserIDFromJWT(token); userID != "" {
			return userID
		}
	}
	
	return ""
}

// extractUserIDFromJWT はJWTトークンからユーザーIDを抽出する
func extractUserIDFromJWT(token string) string {
	// 簡易的な実装：JWTの署名検証なしでペイロードを取得
	// 本番環境では適切な署名検証が必要
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	
	// Base64デコード（パディング調整）
	payload := parts[1]
	// URLセーフなBase64の場合、パディングが省略されることがある
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}
	
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	
	// JSONパース
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return ""
	}
	
	// user_idまたはsubからユーザーIDを取得
	if userID, ok := claims["user_id"].(string); ok && userID != "" {
		return userID
	}
	
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	
	return ""
}

// DeleteSocialAccount はソーシャルアカウントを削除する
func (h *SocialHandler) DeleteSocialAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// URLからアカウントIDを取得
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/social/accounts/")
	accountID := strings.Split(path, "/")[0]

	if accountID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "account ID is required")
		return
	}

	if err := h.repo.Delete(r.Context(), accountID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete social account: %v", err))
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "social account deleted successfully",
	})
}

// GetSupportedProviders はサポートされているプロバイダー一覧を返す
func (h *SocialHandler) GetSupportedProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	providers := make([]map[string]interface{}, 0)
	
	// OAuth2設定が存在する場合のみプロバイダーを追加
	if h.oauth2Configs != nil {
		for provider := range h.oauth2Configs {
			// プロバイダー固有のスコープを取得
			scopes := []string{"email", "profile"}
			switch provider {
			case models.ProviderGoogle:
				scopes = []string{"openid", "email", "profile"}
			case models.ProviderGitHub:
				scopes = []string{"user:email"}
			case models.ProviderDiscord:
				scopes = []string{"identify", "email"}
			}
			
			providers = append(providers, map[string]interface{}{
				"provider": provider,
				"name":     models.GetProviderDisplayName(provider),
				"enabled":  true,
				"scopes":   scopes,
			})
		}
	}

	// 常に有効なレスポンスを返す（設定されていない場合は空の配列）
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// extractProviderID はプロバイダー別にユーザーIDを抽出する
func extractProviderID(provider string, userInfo map[string]interface{}) (string, error) {
	switch provider {
	case models.ProviderGoogle:
		if id, ok := userInfo["id"].(string); ok && id != "" {
			return id, nil
		}
	case models.ProviderGitHub:
		if id, ok := userInfo["id"].(float64); ok {
			return fmt.Sprintf("%.0f", id), nil
		}
	case models.ProviderDiscord:
		if id, ok := userInfo["id"].(string); ok && id != "" {
			return id, nil
		}
	}
	
	return "", fmt.Errorf("provider ID not found for provider %s", provider)
}

// extractEmail はユーザー情報からメールアドレスを抽出する
func extractEmail(userInfo map[string]interface{}) (string, bool) {
	if email, ok := userInfo["email"].(string); ok && email != "" {
		return email, true
	}
	return "", false
}

// extractDisplayName はプロバイダー別に表示名を抽出する
func extractDisplayName(provider string, userInfo map[string]interface{}) (string, bool) {
	switch provider {
	case models.ProviderGoogle:
		if name, ok := userInfo["name"].(string); ok && name != "" {
			return name, true
		}
	case models.ProviderGitHub:
		if name, ok := userInfo["name"].(string); ok && name != "" {
			return name, true
		}
		if login, ok := userInfo["login"].(string); ok && login != "" {
			return login, true
		}
	case models.ProviderDiscord:
		if username, ok := userInfo["username"].(string); ok && username != "" {
			return username, true
		}
	}
	
	return "", false
}

// writeJSONResponse はJSONレスポンスを書き込む
func writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// エラーログを記録する（実際のアプリケーションではロガーを使用）
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// writeErrorResponse はエラーレスポンスを書き込む
func writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	response := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	writeJSONResponse(w, statusCode, response)
}

// handleNewSocialLogin は新しいソーシャルログインを処理する
func (h *SocialHandler) handleNewSocialLogin(ctx context.Context, provider, providerID string, userInfo map[string]interface{}) (string, *models.SocialAccount, error) {
	// メールアドレスを取得
	email, hasEmail := extractEmail(userInfo)
	if !hasEmail {
		return "", nil, fmt.Errorf("email not provided by %s", provider)
	}

	// メールアドレスで既存ユーザーを検索
	existingUserID, err := h.findUserByEmail(ctx, email)
	var userID string

	if err != nil || existingUserID == "" {
		// 既存ユーザーが見つからない場合は新規作成
		username := h.generateUsernameFromEmail(email)
		userID, err = h.createUser(ctx, username, email)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create user: %v", err)
		}
	} else {
		// 既存ユーザーを使用
		userID = existingUserID
	}

	// ソーシャルアカウントを作成
	displayName, _ := extractDisplayName(provider, userInfo)
	socialAccount, err := models.NewSocialAccount(
		userID,
		provider,
		providerID,
		email,
		displayName,
		userInfo,
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create social account: %v", err)
	}

	// ソーシャルアカウントを保存
	if err := h.repo.Create(ctx, socialAccount); err != nil {
		return "", nil, fmt.Errorf("failed to save social account: %v", err)
	}

	return userID, socialAccount, nil
}

// findUserByEmail はメールアドレスでユーザーを検索する
func (h *SocialHandler) findUserByEmail(ctx context.Context, email string) (string, error) {
	// user-serviceのAPIエンドポイントを呼び出し
	url := fmt.Sprintf("%s/api/v1/users/email/%s", h.userServiceURL, email)
	fmt.Printf("DEBUG: Looking for user by email: %s, URL: %s\n", email, url)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // ユーザーが見つからない（エラーではない）
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("user service returned status %d", resp.StatusCode)
	}

	var response UserServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if !response.Success {
		return "", fmt.Errorf("user service error: %s", response.Error)
	}

	// ユーザーIDを抽出
	if userMap, ok := response.User.(map[string]interface{}); ok {
		if id, ok := userMap["id"].(string); ok {
			return id, nil
		}
	}

	return "", fmt.Errorf("invalid user response format")
}

// createUser は新規ユーザーを作成する
func (h *SocialHandler) createUser(ctx context.Context, username, email string) (string, error) {
	// user-serviceのAPIエンドポイントを呼び出し
	url := fmt.Sprintf("%s/api/v1/users/register", h.userServiceURL)
	fmt.Printf("DEBUG: Creating new user - username: %s, email: %s, URL: %s\n", username, email, url)
	
	// ランダムパスワードを生成（ソーシャルログインなので使用されない）
	password := fmt.Sprintf("social_%d", time.Now().Unix())
	
	requestBody := CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password, // ソーシャルログイン用のダミーパスワード
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("user service returned status %d", resp.StatusCode)
	}

	var response UserServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	if !response.Success {
		return "", fmt.Errorf("user service error: %s", response.Error)
	}

	// ユーザーIDを抽出
	if userMap, ok := response.User.(map[string]interface{}); ok {
		if id, ok := userMap["id"].(string); ok {
			return id, nil
		}
	}

	return "", fmt.Errorf("invalid user creation response format")
}

// generateUsernameFromEmail はメールアドレスからユーザー名を生成する
func (h *SocialHandler) generateUsernameFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return "user"
}