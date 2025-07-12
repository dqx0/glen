package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/dqx0/glen/auth-service/internal/models"
	"github.com/dqx0/glen/auth-service/internal/repository"
)

var (
	ErrInvalidUserID       = errors.New("invalid user ID")
	ErrInvalidUsername     = errors.New("invalid username")
	ErrEmptyScopes         = errors.New("empty scopes")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenExpired        = errors.New("token expired")
	ErrUnauthorized        = errors.New("unauthorized")
)

// TokenRepository はトークンの永続化を担当するインターフェース
type TokenRepository interface {
	Create(ctx context.Context, token *models.Token) error
	GetByID(ctx context.Context, id string) (*models.Token, error)
	GetByUserID(ctx context.Context, userID string) ([]*models.Token, error)
	GetByTypeAndUserID(ctx context.Context, tokenType, userID string) ([]*models.Token, error)
	Update(ctx context.Context, token *models.Token) error
	Delete(ctx context.Context, id string) error
	DeleteExpiredTokens(ctx context.Context) (int64, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*models.Token, error)
}

// JWTServiceInterface はJWT関連の操作を提供するインターフェース
type JWTServiceInterface interface {
	GenerateAccessToken(userID, username string, scopes []string) (string, string, error)
	ValidateToken(tokenString string) (*Claims, error)
}

// LoginResponse はログイン成功時のレスポンス
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse はトークンリフレッシュ時のレスポンス
type RefreshResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// APIKeyResponse はAPIキー作成時のレスポンス
type APIKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	APIKey    string    `json:"api_key"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthService は認証関連のビジネスロジックを提供する
type AuthService struct {
	tokenRepo  TokenRepository
	jwtService JWTServiceInterface
}

// NewAuthService は新しいAuthServiceを作成する
func NewAuthService(tokenRepo TokenRepository, jwtService JWTServiceInterface) *AuthService {
	return &AuthService{
		tokenRepo:  tokenRepo,
		jwtService: jwtService,
	}
}

// Login はユーザーログインを処理し、アクセストークンとリフレッシュトークンを発行する
func (s *AuthService) Login(ctx context.Context, userID, username, sessionName string, scopes []string) (*LoginResponse, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	if username == "" {
		return nil, ErrInvalidUsername
	}
	
	if len(scopes) == 0 {
		return nil, ErrEmptyScopes
	}

	// アクセストークン生成
	accessToken, _, err := s.jwtService.GenerateAccessToken(userID, username, scopes)
	if err != nil {
		return nil, err
	}

	// リフレッシュトークン作成
	refreshToken, err := models.NewRefreshToken(userID, sessionName, scopes)
	if err != nil {
		return nil, err
	}

	// リフレッシュトークンをデータベースに保存
	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(AccessTokenDuration.Seconds()),
		RefreshToken: refreshToken.GetPlainToken(),
	}, nil
}

// RefreshToken はリフレッシュトークンを使用して新しいアクセストークンを発行する
func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenValue, username string) (*RefreshResponse, error) {
	if refreshTokenValue == "" {
		return nil, ErrInvalidRefreshToken
	}

	// リフレッシュトークンのハッシュ化
	hash := sha256.Sum256([]byte(refreshTokenValue))
	tokenHash := hex.EncodeToString(hash[:])

	// データベースからトークンを取得
	token, err := s.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	// トークンタイプの確認
	if token.Type != models.TokenTypeRefresh {
		return nil, ErrInvalidRefreshToken
	}

	// 期限チェック
	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	// 新しいアクセストークン生成
	accessToken, _, err := s.jwtService.GenerateAccessToken(token.UserID, username, token.Scopes)
	if err != nil {
		return nil, err
	}

	// リフレッシュトークンの最終使用時刻を更新
	token.UpdateLastUsed()
	if err := s.tokenRepo.Update(ctx, token); err != nil {
		return nil, err
	}

	return &RefreshResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(AccessTokenDuration.Seconds()),
	}, nil
}

// CreateAPIKey はAPIキーを作成する
func (s *AuthService) CreateAPIKey(ctx context.Context, userID, name string, scopes []string) (*APIKeyResponse, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	if name == "" {
		return nil, errors.New("API key name is required")
	}

	if len(scopes) == 0 {
		return nil, ErrEmptyScopes
	}

	// APIキー作成
	apiKey, err := models.NewAPIKey(userID, name, scopes)
	if err != nil {
		return nil, err
	}

	// データベースに保存
	if err := s.tokenRepo.Create(ctx, apiKey); err != nil {
		return nil, err
	}

	return &APIKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		APIKey:    apiKey.GetPlainToken(),
		Scopes:    apiKey.Scopes,
		CreatedAt: apiKey.CreatedAt,
	}, nil
}

// RevokeToken はトークンを無効化する
func (s *AuthService) RevokeToken(ctx context.Context, tokenID, userID string) error {
	// トークンの存在確認
	token, err := s.tokenRepo.GetByID(ctx, tokenID)
	if err != nil {
		return err
	}

	// 所有者確認
	if token.UserID != userID {
		return ErrUnauthorized
	}

	// トークン削除
	return s.tokenRepo.Delete(ctx, tokenID)
}

// ListUserTokens はユーザーのトークン一覧を取得する
func (s *AuthService) ListUserTokens(ctx context.Context, userID string) ([]*models.Token, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}

	return s.tokenRepo.GetByUserID(ctx, userID)
}

// ValidateAPIKey はAPIキーを検証する
func (s *AuthService) ValidateAPIKey(ctx context.Context, apiKeyValue string) (*models.Token, error) {
	if apiKeyValue == "" {
		return nil, errors.New("API key is required")
	}

	// APIキーのハッシュ化
	hash := sha256.Sum256([]byte(apiKeyValue))
	tokenHash := hex.EncodeToString(hash[:])

	// データベースからトークンを取得
	token, err := s.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// トークンタイプの確認
	if token.Type != models.TokenTypeAPIKey {
		return nil, errors.New("invalid API key")
	}

	// APIキーは期限なしだが、念のため確認
	if token.IsExpired() {
		return nil, ErrTokenExpired
	}

	// 最終使用時刻を更新
	token.UpdateLastUsed()
	if err := s.tokenRepo.Update(ctx, token); err != nil {
		// 更新エラーはログに記録するが、認証は継続
		// 実際のアプリケーションではロガーを使用
	}

	return token, nil
}

// CleanupExpiredTokens は期限切れトークンを削除する
func (s *AuthService) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	return s.tokenRepo.DeleteExpiredTokens(ctx)
}