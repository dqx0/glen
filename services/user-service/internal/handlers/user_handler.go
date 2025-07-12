package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/dqx0/glen/user-service/internal/models"
	"github.com/dqx0/glen/user-service/internal/service"
)

// UserServiceInterface はサービス層のインターフェース
type UserServiceInterface interface {
	Register(ctx context.Context, username, email, password string) (*models.User, error)
	Login(ctx context.Context, username, password string) (*models.User, error)
	GetUser(ctx context.Context, username string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	UpdatePassword(ctx context.Context, username, newPassword string) error
	VerifyEmail(ctx context.Context, username string) error
}

type UserHandler struct {
	userService UserServiceInterface
}

func NewUserHandler(userService UserServiceInterface) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// RegisterRequest はユーザー登録リクエストの構造体
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// LoginRequest はログインリクエストの構造体
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserResponse はユーザー情報のレスポンス構造体
type UserResponse struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	IsActive      bool   `json:"is_active"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ErrorResponse はエラーレスポンスの構造体
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// SuccessResponse は成功レスポンスの構造体
type SuccessResponse struct {
	Success bool         `json:"success"`
	User    UserResponse `json:"user"`
}

// Register はユーザー登録を処理する
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// バリデーション
	if req.Username == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "username is required")
		return
	}

	// ユーザー登録
	user, err := h.userService.Register(r.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUsernameExists):
			h.writeErrorResponse(w, http.StatusConflict, "username already exists")
		case errors.Is(err, service.ErrEmailExists):
			h.writeErrorResponse(w, http.StatusConflict, "email already exists")
		default:
			if errors.Is(err, models.ErrInvalidUsername) || errors.Is(err, models.ErrInvalidEmail) || errors.Is(err, models.ErrInvalidPassword) {
				h.writeErrorResponse(w, http.StatusBadRequest, err.Error())
			} else {
				// デバッグ用：実際のエラーをログに出力
				fmt.Printf("Registration error: %v\n", err)
				h.writeErrorResponse(w, http.StatusInternalServerError, "internal server error")
			}
		}
		return
	}

	// 成功レスポンス
	userResp := UserResponse{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive(),
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		User:    userResp,
	})
}

// Login はユーザーログインを処理する
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// バリデーション
	if req.Username == "" || req.Password == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "username and password are required")
		return
	}

	// ログイン
	user, err := h.userService.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			h.writeErrorResponse(w, http.StatusUnauthorized, "invalid credentials")
		case errors.Is(err, service.ErrPasswordAuthNotAvailable):
			h.writeErrorResponse(w, http.StatusBadRequest, "password authentication not available for this user")
		default:
			h.writeErrorResponse(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// 成功レスポンス
	userResp := UserResponse{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive(),
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		User:    userResp,
	})
}

// GetUser はユーザー情報を取得する
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "username is required")
		return
	}

	user, err := h.userService.GetUser(r.Context(), username)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			h.writeErrorResponse(w, http.StatusNotFound, "user not found")
		default:
			h.writeErrorResponse(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	// 成功レスポンス
	userResp := UserResponse{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive(),
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		User:    userResp,
	})
}

// GetUserByID handles requests to get a user by their ID
func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract user ID from URL parameter
	userID := chi.URLParam(r, "user_id")
	if userID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "user ID is required")
		return
	}

	user, err := h.userService.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			h.writeErrorResponse(w, http.StatusNotFound, "user not found")
			return
		}
		h.writeErrorResponse(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	userResp := UserResponse{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		IsActive:      user.IsActive(),
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		User:    userResp,
	})
}

// WebAuthn関連のハンドラー

// WebAuthnRegisterStart handles WebAuthn registration start requests
func (h *UserHandler) WebAuthnRegisterStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		UserID      string `json:"user_id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == "" || req.Username == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "user_id and username are required")
		return
	}

	// Generate a basic registration challenge response
	// This is a simplified implementation for frontend compatibility
	challenge := generateChallenge()
	
	response := map[string]interface{}{
		"challenge": challenge,
		"user_id":   req.UserID,
		"timeout":   60000, // 60 seconds
		"rp": map[string]string{
			"name": "Glen ID",
			"id":   "glen.dqx0.com",
		},
		"user": map[string]interface{}{
			"id":          req.UserID,
			"name":        req.Username,
			"displayName": getDisplayName(req.DisplayName, req.Username),
		},
		"pubKeyCredParams": []map[string]interface{}{
			{"type": "public-key", "alg": -7},  // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"authenticatorSelection": map[string]interface{}{
			"userVerification": "preferred",
		},
		"attestation": "none",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// WebAuthnRegisterFinish handles WebAuthn registration finish requests
func (h *UserHandler) WebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		UserID              string `json:"user_id"`
		AttestationResponse struct {
			ID       string `json:"id"`
			RawID    string `json:"rawId"`
			Type     string `json:"type"`
			Response struct {
				ClientDataJSON    string `json:"clientDataJSON"`
				AttestationObject string `json:"attestationObject"`
			} `json:"response"`
		} `json:"attestationResponse"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "user_id is required")
		return
	}

	// For now, just return a success response
	// In a full implementation, this would validate the attestation and store the credential
	response := map[string]interface{}{
		"success": true,
		"credential": map[string]interface{}{
			"id":              req.AttestationResponse.ID,
			"user_id":         req.UserID,
			"credential_id":   req.AttestationResponse.RawID,
			"name":            "Security Key",
			"attestation_type": "none",
			"transport":       []string{"internal"},
			"created_at":      time.Now().Format("2006-01-02T15:04:05Z07:00"),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// WebAuthnAuthenticateStart handles WebAuthn authentication start requests
func (h *UserHandler) WebAuthnAuthenticateStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Username string `json:"username,omitempty"`
		UserID   string `json:"user_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Generate a basic authentication challenge response
	challenge := generateChallenge()
	
	response := map[string]interface{}{
		"challenge": challenge,
		"timeout":   60000, // 60 seconds
		"rpId":      "glen.dqx0.com",
		"allowCredentials": []interface{}{}, // Empty for now
		"userVerification": "preferred",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// WebAuthnAuthenticateFinish handles WebAuthn authentication finish requests
func (h *UserHandler) WebAuthnAuthenticateFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		AssertionResponse struct {
			ID       string `json:"id"`
			RawID    string `json:"rawId"`
			Type     string `json:"type"`
			Response struct {
				ClientDataJSON    string `json:"clientDataJSON"`
				AuthenticatorData string `json:"authenticatorData"`
				Signature         string `json:"signature"`
				UserHandle        string `json:"userHandle,omitempty"`
			} `json:"response"`
		} `json:"assertionResponse"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// For now, just return a success response
	// In a full implementation, this would validate the assertion
	response := map[string]interface{}{
		"success": true,
		"verified": true,
		"user": map[string]interface{}{
			"id":       "test-user-id",
			"username": "testuser",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetWebAuthnCredentials handles GET requests for WebAuthn credentials
func (h *UserHandler) GetWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	// Return empty credentials list for now - this is a minimal implementation
	// In a full implementation, this would fetch credentials from the database
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"credentials": []interface{}{},
	})
}

// DeleteWebAuthnCredential handles DELETE requests for WebAuthn credentials
func (h *UserHandler) DeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	h.writeErrorResponse(w, http.StatusNotImplemented, "WebAuthn credential deletion not yet implemented")
}

// HandleWebAuthnCredentials handles WebAuthn credentials management
func (h *UserHandler) HandleWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.GetWebAuthnCredentials(w, r)
	case "DELETE":
		h.DeleteWebAuthnCredential(w, r)
	default:
		h.writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// writeErrorResponse はエラーレスポンスを書き込む
func (h *UserHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Success: false,
		Error:   message,
	})
}

// generateChallenge generates a random challenge for WebAuthn
func generateChallenge() string {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		// Fallback to a deterministic challenge if random generation fails
		copy(challenge, []byte("challenge-fallback-glen-id-platform"))
	}
	return base64.URLEncoding.EncodeToString(challenge)
}

// getDisplayName returns the display name, falling back to username if empty
func getDisplayName(displayName, username string) string {
	if displayName != "" {
		return displayName
	}
	return username
}
