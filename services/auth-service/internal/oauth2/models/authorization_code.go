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
	// Authorization code settings
	AuthorizationCodeLength   = 32           // bytes
	AuthorizationCodeDuration = 10 * time.Minute // 10 minutes
	
	// PKCE settings
	PKCEMethodPlain = "plain"
	PKCEMethodS256  = "S256"
)

var (
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
	ErrCodeExpired             = errors.New("authorization code expired")
	ErrCodeAlreadyUsed         = errors.New("authorization code already used")
	ErrInvalidPKCE             = errors.New("invalid PKCE challenge")
)

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	ID                    string     `json:"id" db:"id"`
	CodeHash              string     `json:"-" db:"code_hash"`
	ClientID              string     `json:"client_id" db:"client_id"`
	UserID                string     `json:"user_id" db:"user_id"`
	RedirectURI           string     `json:"redirect_uri" db:"redirect_uri"`
	Scopes                []string   `json:"scopes" db:"-"`
	ScopesJSON            string     `json:"-" db:"scopes"`
	State                 string     `json:"state" db:"state"`
	CodeChallenge         string     `json:"-" db:"code_challenge"`         // PKCE
	CodeChallengeMethod   string     `json:"-" db:"code_challenge_method"`  // PKCE
	ExpiresAt             time.Time  `json:"expires_at" db:"expires_at"`
	UsedAt                *time.Time `json:"used_at" db:"used_at"`
	CreatedAt             time.Time  `json:"created_at" db:"created_at"`
	
	// Plain text code (only available during creation)
	plainCode string `json:"-"`
}

// NewAuthorizationCode creates a new authorization code
func NewAuthorizationCode(clientID, userID, redirectURI string, scopes []string, state string) (*AuthorizationCode, error) {
	if clientID == "" || userID == "" || redirectURI == "" {
		return nil, ErrInvalidAuthorizationCode
	}
	
	if len(scopes) == 0 {
		return nil, errors.New("scopes are required")
	}
	
	plainCode, codeHash, err := generateCodeAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate authorization code: %w", err)
	}
	
	now := time.Now()
	
	code := &AuthorizationCode{
		ID:          uuid.New().String(),
		CodeHash:    codeHash,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
		State:       state,
		ExpiresAt:   now.Add(AuthorizationCodeDuration),
		CreatedAt:   now,
		plainCode:   plainCode,
	}
	
	// Serialize scopes for database storage
	if err := code.SerializeForDB(); err != nil {
		return nil, fmt.Errorf("failed to serialize authorization code: %w", err)
	}
	
	return code, nil
}

// NewAuthorizationCodeWithPKCE creates a new authorization code with PKCE support
func NewAuthorizationCodeWithPKCE(clientID, userID, redirectURI string, scopes []string, state, codeChallenge, codeChallengeMethod string) (*AuthorizationCode, error) {
	code, err := NewAuthorizationCode(clientID, userID, redirectURI, scopes, state)
	if err != nil {
		return nil, err
	}
	
	// Validate PKCE parameters
	if codeChallenge != "" {
		if codeChallengeMethod != PKCEMethodPlain && codeChallengeMethod != PKCEMethodS256 {
			return nil, ErrInvalidPKCE
		}
		
		code.CodeChallenge = codeChallenge
		code.CodeChallengeMethod = codeChallengeMethod
	}
	
	return code, nil
}

// ValidateCode validates a plain text authorization code against the stored hash
func (ac *AuthorizationCode) ValidateCode(plainCode string) bool {
	if plainCode == "" || ac.CodeHash == "" {
		return false
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(plainCode))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash == ac.CodeHash
}

// GetPlainCode returns the plain text authorization code (only available during creation)
func (ac *AuthorizationCode) GetPlainCode() string {
	return ac.plainCode
}

// IsExpired checks if the authorization code is expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsUsed checks if the authorization code has been used
func (ac *AuthorizationCode) IsUsed() bool {
	return ac.UsedAt != nil
}

// MarkAsUsed marks the authorization code as used
func (ac *AuthorizationCode) MarkAsUsed() {
	now := time.Now()
	ac.UsedAt = &now
}

// ValidatePKCE validates the PKCE code verifier against the stored challenge
func (ac *AuthorizationCode) ValidatePKCE(codeVerifier string) bool {
	if ac.CodeChallenge == "" {
		// PKCE not used, validation passes
		return true
	}
	
	if codeVerifier == "" {
		// PKCE challenge present but no verifier provided
		return false
	}
	
	switch ac.CodeChallengeMethod {
	case PKCEMethodPlain:
		return codeVerifier == ac.CodeChallenge
		
	case PKCEMethodS256:
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		hash := hex.EncodeToString(hasher.Sum(nil))
		return hash == ac.CodeChallenge
		
	default:
		return false
	}
}

// IsValid performs comprehensive validation of the authorization code
func (ac *AuthorizationCode) IsValid(plainCode string, codeVerifier string) error {
	if ac.IsExpired() {
		return ErrCodeExpired
	}
	
	if ac.IsUsed() {
		return ErrCodeAlreadyUsed
	}
	
	if !ac.ValidateCode(plainCode) {
		return ErrInvalidAuthorizationCode
	}
	
	if !ac.ValidatePKCE(codeVerifier) {
		return ErrInvalidPKCE
	}
	
	return nil
}

// SerializeForDB converts array fields to JSON strings for database storage
func (ac *AuthorizationCode) SerializeForDB() error {
	var err error
	
	ac.ScopesJSON, err = serializeStringArray(ac.Scopes)
	if err != nil {
		return fmt.Errorf("failed to serialize scopes: %w", err)
	}
	
	return nil
}

// DeserializeFromDB converts JSON strings from database to array fields
func (ac *AuthorizationCode) DeserializeFromDB() error {
	var err error
	
	ac.Scopes, err = deserializeStringArray(ac.ScopesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize scopes: %w", err)
	}
	
	return nil
}

// Helper functions

func generateCodeAndHash() (plainCode, codeHash string, err error) {
	// Generate random bytes
	codeBytes := make([]byte, AuthorizationCodeLength)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random code: %w", err)
	}
	
	// Plain text code (hex format)
	plainCode = hex.EncodeToString(codeBytes)
	
	// SHA256 hash
	hasher := sha256.New()
	hasher.Write([]byte(plainCode))
	codeHash = hex.EncodeToString(hasher.Sum(nil))
	
	return plainCode, codeHash, nil
}

