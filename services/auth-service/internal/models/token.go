package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	TokenTypeRefresh = "refresh_token"
	TokenTypeAPIKey  = "api_key"
	
	// Token寿命
	RefreshTokenDuration = 30 * 24 * time.Hour // 30日
	
	// Token長さ
	TokenLength = 32 // バイト
)

var (
	ErrInvalidUserID    = errors.New("invalid user ID")
	ErrInvalidTokenName = errors.New("invalid token name")
	ErrEmptyScopes      = errors.New("empty scopes")
	ErrInvalidTokenType = errors.New("invalid token type")
)

type Token struct {
	ID         string    `json:"id" db:"id"`
	UserID     string    `json:"user_id" db:"user_id"`
	Type       string    `json:"token_type" db:"token_type"`
	TokenHash  string    `json:"-" db:"token_hash"`
	Name       string    `json:"name" db:"name"`
	Scopes     []string  `json:"scopes" db:"scopes"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at" db:"last_used_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	
	// プレーンテキストトークン（DBには保存しない）
	plainToken string `json:"-"`
}

// NewRefreshToken は新しいRefresh Tokenを作成する
func NewRefreshToken(userID, name string, scopes []string) (*Token, error) {
	if err := validateTokenInput(userID, name, scopes); err != nil {
		return nil, err
	}
	
	plainToken, tokenHash, err := generateTokenAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	
	now := time.Now()
	
	return &Token{
		ID:         uuid.New().String(),
		UserID:     userID,
		Type:       TokenTypeRefresh,
		TokenHash:  tokenHash,
		Name:       name,
		Scopes:     scopes,
		ExpiresAt:  now.Add(RefreshTokenDuration),
		LastUsedAt: now,
		CreatedAt:  now,
		plainToken: plainToken,
	}, nil
}

// NewAPIKey は新しいAPI Keyを作成する
func NewAPIKey(userID, name string, scopes []string) (*Token, error) {
	if err := validateTokenInput(userID, name, scopes); err != nil {
		return nil, err
	}
	
	plainToken, tokenHash, err := generateTokenAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	
	now := time.Now()
	
	return &Token{
		ID:         uuid.New().String(),
		UserID:     userID,
		Type:       TokenTypeAPIKey,
		TokenHash:  tokenHash,
		Name:       name,
		Scopes:     scopes,
		ExpiresAt:  time.Time{}, // API Keyは期限なし
		LastUsedAt: now,
		CreatedAt:  now,
		plainToken: plainToken,
	}, nil
}

// IsExpired はトークンが期限切れかどうかを確認する
func (t *Token) IsExpired() bool {
	if t.ExpiresAt.IsZero() {
		return false // API Keyは期限なし
	}
	return time.Now().After(t.ExpiresAt)
}

// ValidateHash はプレーンテキストトークンがハッシュと一致するかを確認する
func (t *Token) ValidateHash(plaintext string) bool {
	if plaintext == "" || t.TokenHash == "" {
		return false
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(plaintext))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash == t.TokenHash
}

// UpdateLastUsed は最終使用時刻を更新する
func (t *Token) UpdateLastUsed() {
	t.LastUsedAt = time.Now()
}

// GetPlainToken はプレーンテキストトークンを返す（作成時のみ利用可能）
func (t *Token) GetPlainToken() string {
	return t.plainToken
}

// validateTokenInput は共通のバリデーションを行う
func validateTokenInput(userID, name string, scopes []string) error {
	if userID == "" {
		return ErrInvalidUserID
	}
	
	if name == "" {
		return ErrInvalidTokenName
	}
	
	if len(scopes) == 0 {
		return ErrEmptyScopes
	}
	
	return nil
}

// generateTokenAndHash はランダムトークンとそのハッシュを生成する
func generateTokenAndHash() (plainToken, tokenHash string, err error) {
	// ランダムバイト生成
	tokenBytes := make([]byte, TokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random token: %w", err)
	}
	
	// プレーンテキストトークン（hex形式）
	plainToken = hex.EncodeToString(tokenBytes)
	
	// SHA256ハッシュ
	hasher := sha256.New()
	hasher.Write([]byte(plainToken))
	tokenHash = hex.EncodeToString(hasher.Sum(nil))
	
	return plainToken, tokenHash, nil
}