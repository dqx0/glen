package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
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
		Status:        user.Status,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
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
		Status:        user.Status,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
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
		Status:        user.Status,
		CreatedAt:     user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		User:    userResp,
	})
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