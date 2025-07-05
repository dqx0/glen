package models

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// サポートするOAuth2プロバイダー
const (
	ProviderGoogle  = "google"
	ProviderGitHub  = "github"
	ProviderDiscord = "discord"
)

var (
	ErrInvalidUserID     = errors.New("invalid user ID")
	ErrInvalidProvider   = errors.New("invalid provider")
	ErrInvalidProviderID = errors.New("invalid provider ID")
)

// SocialAccount はソーシャルアカウント連携情報を表す
type SocialAccount struct {
	ID          string                 `json:"id" db:"id"`
	UserID      string                 `json:"user_id" db:"user_id"`
	Provider    string                 `json:"provider" db:"provider"`
	ProviderID  string                 `json:"provider_id" db:"provider_id"`
	Email       string                 `json:"email" db:"email"`
	DisplayName string                 `json:"display_name" db:"display_name"`
	ProfileData map[string]interface{} `json:"profile_data" db:"profile_data"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// NewSocialAccount は新しいソーシャルアカウントを作成する
func NewSocialAccount(userID, provider, providerID, email, displayName string, profileData map[string]interface{}) (*SocialAccount, error) {
	if userID == "" {
		return nil, ErrInvalidUserID
	}
	
	if !IsValidProvider(provider) {
		return nil, ErrInvalidProvider
	}
	
	if providerID == "" {
		return nil, ErrInvalidProviderID
	}
	
	now := time.Now()
	
	return &SocialAccount{
		ID:          uuid.New().String(),
		UserID:      userID,
		Provider:    provider,
		ProviderID:  providerID,
		Email:       email,
		DisplayName: displayName,
		ProfileData: profileData,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// UpdateProfile はプロフィール情報を更新する
func (sa *SocialAccount) UpdateProfile(email, displayName string, profileData map[string]interface{}) {
	sa.Email = email
	sa.DisplayName = displayName
	sa.ProfileData = profileData
	sa.UpdatedAt = time.Now()
}

// IsLinkedToUser は指定されたユーザーに紐づいているかチェックする
func (sa *SocialAccount) IsLinkedToUser(userID string) bool {
	return sa.UserID == userID
}

// GetProfileValue はプロフィールデータから指定されたキーの値を取得する
func (sa *SocialAccount) GetProfileValue(key string) (interface{}, bool) {
	if sa.ProfileData == nil {
		return nil, false
	}
	
	value, exists := sa.ProfileData[key]
	return value, exists
}

// IsValidProvider は有効なプロバイダーかチェックする
func IsValidProvider(provider string) bool {
	switch provider {
	case ProviderGoogle, ProviderGitHub, ProviderDiscord:
		return true
	default:
		return false
	}
}

// GetSupportedProviders はサポートされているプロバイダー一覧を返す
func GetSupportedProviders() []string {
	return []string{ProviderGoogle, ProviderGitHub, ProviderDiscord}
}

// GetProviderDisplayName はプロバイダーの表示名を返す
func GetProviderDisplayName(provider string) string {
	switch provider {
	case ProviderGoogle:
		return "Google"
	case ProviderGitHub:
		return "GitHub"
	case ProviderDiscord:
		return "Discord"
	default:
		return "Unknown"
	}
}

// OAuth2Config は各プロバイダーのOAuth2設定を保持する
type OAuth2Config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
}

// GetDefaultOAuth2Config はプロバイダーのデフォルトOAuth2設定を返す
func GetDefaultOAuth2Config(provider string) *OAuth2Config {
	switch provider {
	case ProviderGoogle:
		return &OAuth2Config{
			AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:    "https://oauth2.googleapis.com/token",
			UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
			Scopes:      []string{"openid", "email", "profile"},
		}
	case ProviderGitHub:
		return &OAuth2Config{
			AuthURL:     "https://github.com/login/oauth/authorize",
			TokenURL:    "https://github.com/login/oauth/access_token",
			UserInfoURL: "https://api.github.com/user",
			Scopes:      []string{"user:email"},
		}
	case ProviderDiscord:
		return &OAuth2Config{
			AuthURL:     "https://discord.com/api/oauth2/authorize",
			TokenURL:    "https://discord.com/api/oauth2/token",
			UserInfoURL: "https://discord.com/api/users/@me",
			Scopes:      []string{"identify", "email"},
		}
	default:
		return nil
	}
}