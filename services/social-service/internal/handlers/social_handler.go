package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
	repo        SocialAccountRepository
	oauth2Configs map[string]*models.OAuth2Config
}

// NewSocialHandler は新しいSocialHandlerを作成する
func NewSocialHandler(repo SocialAccountRepository, oauth2Configs map[string]*models.OAuth2Config) *SocialHandler {
	return &SocialHandler{
		repo:          repo,
		oauth2Configs: oauth2Configs,
	}
}

// AuthorizeRequest は認証開始のリクエスト
type AuthorizeRequest struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
}

// AuthorizeResponse は認証URLのレスポンス
type AuthorizeResponse struct {
	AuthURL  string `json:"auth_url"`
	Provider string `json:"provider"`
	State    string `json:"state"`
}

// CallbackRequest はOAuth2コールバックのリクエスト
type CallbackRequest struct {
	Provider string `json:"provider"`
	Code     string `json:"code"`
	State    string `json:"state"`
	UserID   string `json:"user_id"`
}

// CallbackResponse はコールバック処理のレスポンス
type CallbackResponse struct {
	SocialAccount *models.SocialAccount `json:"social_account"`
	IsNewAccount  bool                  `json:"is_new_account"`
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

// HandleCallback はOAuth2コールバックを処理する
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

	// 既存のソーシャルアカウントを確認
	existingAccount, err := h.repo.GetByProviderAndProviderID(r.Context(), req.Provider, providerID)
	isNewAccount := err != nil

	if isNewAccount {
		// 新しいソーシャルアカウントを作成
		email, _ := extractEmail(userInfo)
		displayName, _ := extractDisplayName(req.Provider, userInfo)

		newAccount, err := models.NewSocialAccount(
			req.UserID,
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

	// ユーザーIDをクエリパラメータから取得
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "user_id is required")
		return
	}

	accounts, err := h.repo.GetByUserID(r.Context(), userID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to get social accounts: %v", err))
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"social_accounts": accounts,
		"count":          len(accounts),
	})
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

	providers := make([]map[string]string, 0, len(h.oauth2Configs))
	for provider := range h.oauth2Configs {
		providers = append(providers, map[string]string{
			"id":   provider,
			"name": models.GetProviderDisplayName(provider),
		})
	}

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