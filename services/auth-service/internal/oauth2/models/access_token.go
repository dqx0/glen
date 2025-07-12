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
	// Token settings
	AccessTokenLength   = 32           // bytes
	AccessTokenDuration = 1 * time.Hour // 1 hour
	RefreshTokenDuration = 30 * 24 * time.Hour // 30 days
	
	// Token types
	TokenTypeBearer = "Bearer"
)

var (
	ErrInvalidAccessToken = errors.New("invalid access token")
	ErrTokenExpired       = errors.New("access token expired")
	ErrTokenRevoked       = errors.New("access token revoked")
)

// OAuth2AccessToken represents an OAuth2 access token
type OAuth2AccessToken struct {
	ID               string     `json:"id" db:"id"`
	TokenHash        string     `json:"-" db:"token_hash"`
	ClientID         string     `json:"client_id" db:"client_id"`
	UserID           string     `json:"user_id" db:"user_id"`
	Scopes           []string   `json:"scopes" db:"-"`
	ScopesJSON       string     `json:"-" db:"scopes"`
	TokenType        string     `json:"token_type" db:"token_type"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at" db:"revoked_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt       time.Time  `json:"last_used_at" db:"last_used_at"`
	
	// Plain text token (only available during creation)
	plainToken string `json:"-"`
}

// OAuth2RefreshToken represents an OAuth2 refresh token
type OAuth2RefreshToken struct {
	ID              string     `json:"id" db:"id"`
	TokenHash       string     `json:"-" db:"token_hash"`
	AccessTokenID   string     `json:"access_token_id" db:"access_token_id"`
	ClientID        string     `json:"client_id" db:"client_id"`
	UserID          string     `json:"user_id" db:"user_id"`
	Scopes          []string   `json:"scopes" db:"-"`
	ScopesJSON      string     `json:"-" db:"scopes"`
	ExpiresAt       time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at" db:"revoked_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt      time.Time  `json:"last_used_at" db:"last_used_at"`
	
	// Plain text token (only available during creation)
	plainToken string `json:"-"`
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// NewAccessToken creates a new access token
func NewAccessToken(clientID, userID string, scopes []string) (*OAuth2AccessToken, error) {
	if clientID == "" || userID == "" {
		return nil, ErrInvalidAccessToken
	}
	
	if len(scopes) == 0 {
		return nil, errors.New("scopes are required")
	}
	
	plainToken, tokenHash, err := generateTokenAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	
	now := time.Now()
	
	token := &OAuth2AccessToken{
		ID:         uuid.New().String(),
		TokenHash:  tokenHash,
		ClientID:   clientID,
		UserID:     userID,
		Scopes:     scopes,
		TokenType:  TokenTypeBearer,
		ExpiresAt:  now.Add(AccessTokenDuration),
		CreatedAt:  now,
		LastUsedAt: now,
		plainToken: plainToken,
	}
	
	// Serialize scopes for database storage
	if err := token.SerializeForDB(); err != nil {
		return nil, fmt.Errorf("failed to serialize access token: %w", err)
	}
	
	return token, nil
}

// NewRefreshToken creates a new refresh token associated with an access token
func NewRefreshToken(accessTokenID, clientID, userID string, scopes []string) (*OAuth2RefreshToken, error) {
	if accessTokenID == "" || clientID == "" || userID == "" {
		return nil, errors.New("invalid refresh token parameters")
	}
	
	if len(scopes) == 0 {
		return nil, errors.New("scopes are required")
	}
	
	plainToken, tokenHash, err := generateTokenAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	
	now := time.Now()
	
	token := &OAuth2RefreshToken{
		ID:            uuid.New().String(),
		TokenHash:     tokenHash,
		AccessTokenID: accessTokenID,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        scopes,
		ExpiresAt:     now.Add(RefreshTokenDuration),
		CreatedAt:     now,
		LastUsedAt:    now,
		plainToken:    plainToken,
	}
	
	// Serialize scopes for database storage
	if err := token.SerializeForDB(); err != nil {
		return nil, fmt.Errorf("failed to serialize refresh token: %w", err)
	}
	
	return token, nil
}

// ValidateToken validates a plain text access token against the stored hash
func (at *OAuth2AccessToken) ValidateToken(plainToken string) bool {
	if plainToken == "" || at.TokenHash == "" {
		return false
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(plainToken))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash == at.TokenHash
}

// GetPlainToken returns the plain text access token (only available during creation)
func (at *OAuth2AccessToken) GetPlainToken() string {
	return at.plainToken
}

// IsExpired checks if the access token is expired
func (at *OAuth2AccessToken) IsExpired() bool {
	return time.Now().After(at.ExpiresAt)
}

// IsRevoked checks if the access token has been revoked
func (at *OAuth2AccessToken) IsRevoked() bool {
	return at.RevokedAt != nil
}

// Revoke marks the access token as revoked
func (at *OAuth2AccessToken) Revoke() {
	now := time.Now()
	at.RevokedAt = &now
}

// UpdateLastUsed updates the last used timestamp
func (at *OAuth2AccessToken) UpdateLastUsed() {
	at.LastUsedAt = time.Now()
}

// IsValid performs comprehensive validation of the access token
func (at *OAuth2AccessToken) IsValid(plainToken string) error {
	if at.IsRevoked() {
		return ErrTokenRevoked
	}
	
	if at.IsExpired() {
		return ErrTokenExpired
	}
	
	if !at.ValidateToken(plainToken) {
		return ErrInvalidAccessToken
	}
	
	return nil
}

// HasScope checks if the access token has a specific scope
func (at *OAuth2AccessToken) HasScope(scope string) bool {
	for _, s := range at.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the access token has any of the specified scopes
func (at *OAuth2AccessToken) HasAnyScope(scopes []string) bool {
	for _, scope := range scopes {
		if at.HasScope(scope) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if the access token has all of the specified scopes
func (at *OAuth2AccessToken) HasAllScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !at.HasScope(scope) {
			return false
		}
	}
	return true
}

// GetExpiresIn returns the number of seconds until the token expires
func (at *OAuth2AccessToken) GetExpiresIn() int64 {
	if at.IsExpired() {
		return 0
	}
	return int64(at.ExpiresAt.Sub(time.Now()).Seconds())
}

// ToTokenResponse converts the access token to a token response
func (at *OAuth2AccessToken) ToTokenResponse(refreshToken string) *TokenResponse {
	return &TokenResponse{
		AccessToken:  at.GetPlainToken(),
		TokenType:    at.TokenType,
		ExpiresIn:    at.GetExpiresIn(),
		RefreshToken: refreshToken,
		Scope:        scopesToString(at.Scopes),
	}
}

// SerializeForDB converts array fields to JSON strings for database storage
func (at *OAuth2AccessToken) SerializeForDB() error {
	var err error
	
	at.ScopesJSON, err = serializeStringArray(at.Scopes)
	if err != nil {
		return fmt.Errorf("failed to serialize scopes: %w", err)
	}
	
	return nil
}

// DeserializeFromDB converts JSON strings from database to array fields
func (at *OAuth2AccessToken) DeserializeFromDB() error {
	var err error
	
	at.Scopes, err = deserializeStringArray(at.ScopesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize scopes: %w", err)
	}
	
	return nil
}

// Refresh token methods

// ValidateToken validates a plain text refresh token against the stored hash
func (rt *OAuth2RefreshToken) ValidateToken(plainToken string) bool {
	if plainToken == "" || rt.TokenHash == "" {
		return false
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(plainToken))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash == rt.TokenHash
}

// GetPlainToken returns the plain text refresh token (only available during creation)
func (rt *OAuth2RefreshToken) GetPlainToken() string {
	return rt.plainToken
}

// IsExpired checks if the refresh token is expired
func (rt *OAuth2RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsRevoked checks if the refresh token has been revoked
func (rt *OAuth2RefreshToken) IsRevoked() bool {
	return rt.RevokedAt != nil
}

// Revoke marks the refresh token as revoked
func (rt *OAuth2RefreshToken) Revoke() {
	now := time.Now()
	rt.RevokedAt = &now
}

// UpdateLastUsed updates the last used timestamp
func (rt *OAuth2RefreshToken) UpdateLastUsed() {
	rt.LastUsedAt = time.Now()
}

// IsValid performs comprehensive validation of the refresh token
func (rt *OAuth2RefreshToken) IsValid(plainToken string) error {
	if rt.IsRevoked() {
		return ErrTokenRevoked
	}
	
	if rt.IsExpired() {
		return ErrTokenExpired
	}
	
	if !rt.ValidateToken(plainToken) {
		return errors.New("invalid refresh token")
	}
	
	return nil
}

// SerializeForDB converts array fields to JSON strings for database storage
func (rt *OAuth2RefreshToken) SerializeForDB() error {
	var err error
	
	rt.ScopesJSON, err = serializeStringArray(rt.Scopes)
	if err != nil {
		return fmt.Errorf("failed to serialize scopes: %w", err)
	}
	
	return nil
}

// DeserializeFromDB converts JSON strings from database to array fields
func (rt *OAuth2RefreshToken) DeserializeFromDB() error {
	var err error
	
	rt.Scopes, err = deserializeStringArray(rt.ScopesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize scopes: %w", err)
	}
	
	return nil
}

// Helper functions

func generateTokenAndHash() (plainToken, tokenHash string, err error) {
	// Generate random bytes
	tokenBytes := make([]byte, AccessTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random token: %w", err)
	}
	
	// Plain text token (hex format)
	plainToken = hex.EncodeToString(tokenBytes)
	
	// SHA256 hash
	hasher := sha256.New()
	hasher.Write([]byte(plainToken))
	tokenHash = hex.EncodeToString(hasher.Sum(nil))
	
	return plainToken, tokenHash, nil
}

func scopesToString(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	
	result := ""
	for i, scope := range scopes {
		if i > 0 {
			result += " "
		}
		result += scope
	}
	return result
}

