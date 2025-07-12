package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// Grant types
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	
	// Response types
	ResponseTypeCode = "code"
	ResponseTypeToken = "token"
	
	// Token endpoint auth methods
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"
	TokenEndpointAuthMethodNone              = "none"
	
	// Client secret length
	ClientSecretLength = 32 // bytes
)

var (
	ErrInvalidClientName        = errors.New("invalid client name")
	ErrInvalidRedirectURIs      = errors.New("invalid redirect URIs")
	ErrInvalidScopes           = errors.New("invalid scopes")
	ErrInvalidGrantTypes       = errors.New("invalid grant types")
	ErrInvalidResponseTypes    = errors.New("invalid response types")
	ErrInvalidAuthMethod       = errors.New("invalid token endpoint auth method")
)

// OAuth2Client represents an OAuth2 client application
type OAuth2Client struct {
	ID                       string    `json:"id" db:"id"`
	UserID                   string    `json:"user_id" db:"user_id"`
	ClientID                 string    `json:"client_id" db:"client_id"`
	ClientSecretHash         string    `json:"-" db:"client_secret_hash"`
	Name                     string    `json:"name" db:"name"`
	Description              string    `json:"description" db:"description"`
	RedirectURIs             []string  `json:"redirect_uris" db:"-"`
	RedirectURIsJSON         string    `json:"-" db:"redirect_uris"`
	Scopes                   []string  `json:"scopes" db:"-"`
	ScopesJSON               string    `json:"-" db:"scopes"`
	GrantTypes               []string  `json:"grant_types" db:"-"`
	GrantTypesJSON           string    `json:"-" db:"grant_types"`
	ResponseTypes            []string  `json:"response_types" db:"-"`
	ResponseTypesJSON        string    `json:"-" db:"response_types"`
	TokenEndpointAuthMethod  string    `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	IsPublic                 bool      `json:"is_public" db:"is_public"`
	IsActive                 bool      `json:"is_active" db:"is_active"`
	CreatedAt                time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                time.Time `json:"updated_at" db:"updated_at"`
	
	// Plain text client secret (only available during creation)
	plainClientSecret string `json:"-"`
}

// NewOAuth2Client creates a new OAuth2 client
func NewOAuth2Client(userID, name, description string, redirectURIs, scopes []string, isPublic bool) (*OAuth2Client, error) {
	if err := validateClientInput(name, redirectURIs, scopes); err != nil {
		return nil, err
	}
	
	clientID := generateClientID()
	plainSecret, secretHash, err := generateClientSecretAndHash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}
	
	// Default grant types and response types
	grantTypes := []string{GrantTypeAuthorizationCode}
	responseTypes := []string{ResponseTypeCode}
	
	if isPublic {
		// Public clients (PKCE) don't use client credentials grant
		grantTypes = []string{GrantTypeAuthorizationCode}
	} else {
		// Confidential clients can use both
		grantTypes = []string{GrantTypeAuthorizationCode, GrantTypeClientCredentials}
	}
	
	// Always include refresh token grant
	grantTypes = append(grantTypes, GrantTypeRefreshToken)
	
	authMethod := TokenEndpointAuthMethodClientSecretBasic
	if isPublic {
		authMethod = TokenEndpointAuthMethodNone
	}
	
	now := time.Now()
	
	client := &OAuth2Client{
		ID:                      uuid.New().String(),
		UserID:                  userID,
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		Name:                    name,
		Description:             description,
		RedirectURIs:            redirectURIs,
		Scopes:                  scopes,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		IsPublic:                isPublic,
		IsActive:                true,
		CreatedAt:               now,
		UpdatedAt:               now,
		plainClientSecret:       plainSecret,
	}
	
	// Serialize arrays to JSON for database storage
	if err := client.SerializeForDB(); err != nil {
		return nil, fmt.Errorf("failed to serialize client data: %w", err)
	}
	
	return client, nil
}

// ValidateClientSecret validates a plain text client secret against the stored hash
func (c *OAuth2Client) ValidateClientSecret(plainSecret string) bool {
	if plainSecret == "" || c.ClientSecretHash == "" {
		return false
	}
	
	hasher := sha256.New()
	hasher.Write([]byte(plainSecret))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	return hash == c.ClientSecretHash
}

// GetPlainClientSecret returns the plain text client secret (only available during creation)
func (c *OAuth2Client) GetPlainClientSecret() string {
	return c.plainClientSecret
}

// IsRedirectURIAllowed checks if a redirect URI is allowed for this client
func (c *OAuth2Client) IsRedirectURIAllowed(redirectURI string) bool {
	for _, allowedURI := range c.RedirectURIs {
		if redirectURI == allowedURI {
			return true
		}
	}
	return false
}

// IsScopeAllowed checks if a scope is allowed for this client
func (c *OAuth2Client) IsScopeAllowed(scope string) bool {
	for _, allowedScope := range c.Scopes {
		if scope == allowedScope {
			return true
		}
	}
	return false
}

// AreScopesAllowed checks if all requested scopes are allowed for this client
func (c *OAuth2Client) AreScopesAllowed(requestedScopes []string) bool {
	for _, scope := range requestedScopes {
		if !c.IsScopeAllowed(scope) {
			return false
		}
	}
	return true
}

// IsGrantTypeAllowed checks if a grant type is allowed for this client
func (c *OAuth2Client) IsGrantTypeAllowed(grantType string) bool {
	for _, allowedType := range c.GrantTypes {
		if grantType == allowedType {
			return true
		}
	}
	return false
}

// IsResponseTypeAllowed checks if a response type is allowed for this client
func (c *OAuth2Client) IsResponseTypeAllowed(responseType string) bool {
	for _, allowedType := range c.ResponseTypes {
		if responseType == allowedType {
			return true
		}
	}
	return false
}

// SerializeForDB converts array fields to JSON strings for database storage
func (c *OAuth2Client) SerializeForDB() error {
	var err error
	
	c.RedirectURIsJSON, err = serializeStringArray(c.RedirectURIs)
	if err != nil {
		return fmt.Errorf("failed to serialize redirect URIs: %w", err)
	}
	
	c.ScopesJSON, err = serializeStringArray(c.Scopes)
	if err != nil {
		return fmt.Errorf("failed to serialize scopes: %w", err)
	}
	
	c.GrantTypesJSON, err = serializeStringArray(c.GrantTypes)
	if err != nil {
		return fmt.Errorf("failed to serialize grant types: %w", err)
	}
	
	c.ResponseTypesJSON, err = serializeStringArray(c.ResponseTypes)
	if err != nil {
		return fmt.Errorf("failed to serialize response types: %w", err)
	}
	
	return nil
}

// DeserializeFromDB converts JSON strings from database to array fields
func (c *OAuth2Client) DeserializeFromDB() error {
	var err error
	
	c.RedirectURIs, err = deserializeStringArray(c.RedirectURIsJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize redirect URIs: %w", err)
	}
	
	c.Scopes, err = deserializeStringArray(c.ScopesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize scopes: %w", err)
	}
	
	c.GrantTypes, err = deserializeStringArray(c.GrantTypesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize grant types: %w", err)
	}
	
	c.ResponseTypes, err = deserializeStringArray(c.ResponseTypesJSON)
	if err != nil {
		return fmt.Errorf("failed to deserialize response types: %w", err)
	}
	
	return nil
}

// UpdateClient updates client information (except client_id and client_secret)
func (c *OAuth2Client) UpdateClient(name, description string, redirectURIs, scopes []string) error {
	if err := validateClientInput(name, redirectURIs, scopes); err != nil {
		return err
	}
	
	c.Name = name
	c.Description = description
	c.RedirectURIs = redirectURIs
	c.Scopes = scopes
	c.UpdatedAt = time.Now()
	
	return c.SerializeForDB()
}

// Deactivate marks the client as inactive
func (c *OAuth2Client) Deactivate() {
	c.IsActive = false
	c.UpdatedAt = time.Now()
}

// Activate marks the client as active
func (c *OAuth2Client) Activate() {
	c.IsActive = true
	c.UpdatedAt = time.Now()
}

// Helper functions

func validateClientInput(name string, redirectURIs, scopes []string) error {
	if strings.TrimSpace(name) == "" {
		return ErrInvalidClientName
	}
	
	if len(redirectURIs) == 0 {
		return ErrInvalidRedirectURIs
	}
	
	// Validate redirect URIs
	for _, uri := range redirectURIs {
		parsedURL, err := url.Parse(uri)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			return ErrInvalidRedirectURIs
		}
	}
	
	if len(scopes) == 0 {
		return ErrInvalidScopes
	}
	
	return nil
}

func generateClientID() string {
	// Generate a client ID with prefix
	return fmt.Sprintf("glen_client_%s", generateRandomString(16))
}

func generateClientSecretAndHash() (plainSecret, secretHash string, err error) {
	// Generate random bytes
	secretBytes := make([]byte, ClientSecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	
	// Plain text secret (hex format)
	plainSecret = hex.EncodeToString(secretBytes)
	
	// SHA256 hash
	hasher := sha256.New()
	hasher.Write([]byte(plainSecret))
	secretHash = hex.EncodeToString(hasher.Sum(nil))
	
	return plainSecret, secretHash, nil
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

func serializeStringArray(arr []string) (string, error) {
	if len(arr) == 0 {
		return "[]", nil
	}
	
	data, err := json.Marshal(arr)
	if err != nil {
		return "", err
	}
	
	return string(data), nil
}

func deserializeStringArray(jsonStr string) ([]string, error) {
	if jsonStr == "" || jsonStr == "[]" {
		return []string{}, nil
	}
	
	var arr []string
	err := json.Unmarshal([]byte(jsonStr), &arr)
	if err != nil {
		return nil, err
	}
	
	return arr, nil
}