package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/dqx0/glen/auth-service/internal/models"
	"github.com/dqx0/glen/auth-service/internal/service"
)

// AuthServiceInterface はAuthServiceのインターフェース
type AuthServiceInterface interface {
	Login(ctx context.Context, userID, username, sessionName string, scopes []string) (*service.LoginResponse, error)
	RefreshToken(ctx context.Context, refreshTokenValue, username string) (*service.RefreshResponse, error)
	CreateAPIKey(ctx context.Context, userID, name string, scopes []string) (*service.APIKeyResponse, error)
	RevokeToken(ctx context.Context, tokenID, userID string) error
	ListUserTokens(ctx context.Context, userID string) ([]*models.Token, error)
	ValidateAPIKey(ctx context.Context, apiKeyValue string) (*models.Token, error)
	CleanupExpiredTokens(ctx context.Context) (int64, error)
}

// LoginRequest はログインリクエスト
type LoginRequest struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	SessionName string   `json:"session_name"`
	Scopes      []string `json:"scopes"`
}

// RefreshTokenRequest はトークンリフレッシュリクエスト
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	Username     string `json:"username"`
}

// CreateAPIKeyRequest はAPIキー作成リクエスト
type CreateAPIKeyRequest struct {
	UserID string   `json:"user_id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// RevokeTokenRequest はトークン無効化リクエスト
type RevokeTokenRequest struct {
	TokenID string `json:"token_id"`
	UserID  string `json:"user_id"`
}

// ErrorResponse はエラーレスポンス
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// AuthHandler は認証関連のHTTPハンドラーを提供する
type AuthHandler struct {
	authService AuthServiceInterface
}

// NewAuthHandler は新しいAuthHandlerを作成する
func NewAuthHandler(authService AuthServiceInterface) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Login はユーザーログインを処理する
// POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	response, err := h.authService.Login(r.Context(), req.UserID, req.Username, req.SessionName, req.Scopes)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// RefreshToken はトークンリフレッシュを処理する
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	response, err := h.authService.RefreshToken(r.Context(), req.RefreshToken, req.Username)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// CreateAPIKey はAPIキー作成を処理する
// POST /api/v1/auth/api-keys
func (h *AuthHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	response, err := h.authService.CreateAPIKey(r.Context(), req.UserID, req.Name, req.Scopes)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, response)
}

// RevokeToken はトークン無効化を処理する
// POST /api/v1/auth/revoke
func (h *AuthHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	err := h.authService.RevokeToken(r.Context(), req.TokenID, req.UserID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"token revoked successfully"}`))
}

// ListTokens はユーザーのトークン一覧を取得する
// GET /api/v1/auth/tokens?user_id=xxx
func (h *AuthHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, "user_id parameter is required")
		return
	}

	tokens, err := h.authService.ListUserTokens(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, tokens)
}

// ValidateAPIKey はAPIキーを検証する（内部API用）
// POST /api/v1/auth/validate-api-key
func (h *AuthHandler) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	token, err := h.authService.ValidateAPIKey(r.Context(), req.APIKey)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// APIキー検証成功時はトークン情報を返す（機密情報は除く）
	response := map[string]interface{}{
		"valid":   true,
		"user_id": token.UserID,
		"scopes":  token.Scopes,
		"name":    token.Name,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// handleServiceError はサービス層のエラーを適切なHTTPレスポンスに変換する
func (h *AuthHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidUserID),
		 errors.Is(err, service.ErrInvalidUsername),
		 errors.Is(err, service.ErrEmptyScopes):
		h.writeError(w, http.StatusBadRequest, err.Error())
	
	case errors.Is(err, service.ErrInvalidRefreshToken),
		 errors.Is(err, service.ErrTokenExpired):
		h.writeError(w, http.StatusUnauthorized, err.Error())
	
	case errors.Is(err, service.ErrTokenNotFound):
		h.writeError(w, http.StatusNotFound, err.Error())
	
	case errors.Is(err, service.ErrUnauthorized):
		h.writeError(w, http.StatusForbidden, err.Error())
	
	default:
		h.writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

// writeJSON はJSONレスポンスを書き込む
func (h *AuthHandler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// エラーログを記録（実際のアプリケーションではロガーを使用）
		http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
	}
}

// writeError はエラーレスポンスを書き込む
func (h *AuthHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	response := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
	}
	h.writeJSON(w, statusCode, response)
}