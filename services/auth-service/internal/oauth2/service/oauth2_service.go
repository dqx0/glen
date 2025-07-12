package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/dqx0/glen/auth-service/internal/oauth2/models"
)

var (
	// Authorization errors
	ErrInvalidClient          = errors.New("invalid_client")
	ErrInvalidRequest         = errors.New("invalid_request")
	ErrInvalidGrant           = errors.New("invalid_grant")
	ErrInvalidScope           = errors.New("invalid_scope")
	ErrUnsupportedGrantType   = errors.New("unsupported_grant_type")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrAccessDenied           = errors.New("access_denied")
	ErrServerError            = errors.New("server_error")
	
	// Client errors
	ErrClientNotFound         = errors.New("client not found")
	ErrInvalidClientSecret    = errors.New("invalid client secret")
	ErrInvalidRedirectURI     = errors.New("invalid redirect URI")
	
	// Token errors
	ErrTokenNotFound          = errors.New("token not found")
	ErrTokenExpired           = errors.New("token expired")
	ErrTokenRevoked           = errors.New("token revoked")
	
	// Authorization code errors
	ErrCodeNotFound           = errors.New("authorization code not found")
	ErrCodeExpired            = errors.New("authorization code expired")
	ErrCodeAlreadyUsed        = errors.New("authorization code already used")
	ErrInvalidCodeVerifier    = errors.New("invalid code verifier")
)

// OAuth2RepositoryInterface defines the interface for OAuth2 repository operations
type OAuth2RepositoryInterface interface {
	// Client operations
	CreateClient(ctx context.Context, client *models.OAuth2Client) error
	GetClientByClientID(ctx context.Context, clientID string) (*models.OAuth2Client, error)
	GetClientByID(ctx context.Context, id string) (*models.OAuth2Client, error)
	GetClientsByUserID(ctx context.Context, userID string) ([]*models.OAuth2Client, error)
	DeleteClient(ctx context.Context, clientID, userID string) error
	
	// Authorization Code operations
	CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error
	GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (*models.AuthorizationCode, error)
	MarkAuthorizationCodeAsUsed(ctx context.Context, codeHash string) error
	CleanupExpiredAuthorizationCodes(ctx context.Context) (int64, error)
	
	// Access Token operations
	CreateAccessToken(ctx context.Context, token *models.OAuth2AccessToken) error
	GetAccessTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2AccessToken, error)
	UpdateAccessTokenLastUsed(ctx context.Context, tokenHash string) error
	RevokeAccessToken(ctx context.Context, tokenHash string) error
	CleanupExpiredAccessTokens(ctx context.Context) (int64, error)
	
	// Refresh Token operations
	CreateRefreshToken(ctx context.Context, token *models.OAuth2RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*models.OAuth2RefreshToken, error)
	UpdateRefreshTokenLastUsed(ctx context.Context, tokenHash string) error
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeRefreshTokensByAccessTokenID(ctx context.Context, accessTokenID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) (int64, error)
}

// OAuth2Service provides OAuth2 authorization server functionality
type OAuth2Service struct {
	repo OAuth2RepositoryInterface
}

// NewOAuth2Service creates a new OAuth2Service
func NewOAuth2Service(repo OAuth2RepositoryInterface) *OAuth2Service {
	return &OAuth2Service{
		repo: repo,
	}
}

// AuthorizeRequest represents an OAuth2 authorization request
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizeResponse represents an OAuth2 authorization response
type AuthorizeResponse struct {
	Code  string
	State string
}

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// Client Management

// CreateClient creates a new OAuth2 client
func (s *OAuth2Service) CreateClient(ctx context.Context, userID, name, description string, redirectURIs, scopes []string, isPublic bool) (*models.OAuth2Client, error) {
	client, err := models.NewOAuth2Client(userID, name, description, redirectURIs, scopes, isPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to create client model: %w", err)
	}
	
	if err := s.repo.CreateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to store client: %w", err)
	}
	
	return client, nil
}

// GetClient retrieves a client by client ID
func (s *OAuth2Service) GetClient(ctx context.Context, clientID string) (*models.OAuth2Client, error) {
	client, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ErrClientNotFound
	}
	return client, nil
}

// GetClientsByUserID retrieves all clients for a user
func (s *OAuth2Service) GetClientsByUserID(ctx context.Context, userID string) ([]*models.OAuth2Client, error) {
	clients, err := s.repo.GetClientsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients for user: %w", err)
	}
	return clients, nil
}

// DeleteClient deletes a client
func (s *OAuth2Service) DeleteClient(ctx context.Context, clientIDOrID, userID string) error {
	// Try to find client by client_id first, then by id
	client, err := s.repo.GetClientByClientID(ctx, clientIDOrID)
	if err != nil {
		// If not found by client_id, try by id
		client, err = s.repo.GetClientByID(ctx, clientIDOrID)
		if err != nil {
			return ErrClientNotFound
		}
	}
	
	if client.UserID != userID {
		return ErrInvalidClient
	}
	
	// Use the actual client_id for deletion
	return s.repo.DeleteClient(ctx, client.ClientID, userID)
}

// ValidateClient validates client credentials
func (s *OAuth2Service) ValidateClient(ctx context.Context, clientID, clientSecret string) (*models.OAuth2Client, error) {
	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	
	// Public clients don't have secrets
	if client.IsPublic {
		if clientSecret != "" {
			return nil, ErrInvalidClient
		}
		return client, nil
	}
	
	// Confidential clients must provide valid secret
	if !client.ValidateClientSecret(clientSecret) {
		return nil, ErrInvalidClientSecret
	}
	
	return client, nil
}

// Authorization Flow

// Authorize handles the OAuth2 authorization request
func (s *OAuth2Service) Authorize(ctx context.Context, userID string, req *AuthorizeRequest) (*AuthorizeResponse, error) {
	// Validate client
	client, err := s.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}
	
	// Validate response type
	if !client.IsResponseTypeAllowed(req.ResponseType) {
		return nil, ErrUnsupportedResponseType
	}
	
	// Only support authorization code flow
	if req.ResponseType != models.ResponseTypeCode {
		return nil, ErrUnsupportedResponseType
	}
	
	// Validate redirect URI
	if !client.IsRedirectURIAllowed(req.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	
	// Parse and validate scopes
	requestedScopes := parseScopes(req.Scope)
	if len(requestedScopes) == 0 {
		return nil, ErrInvalidScope
	}
	
	if !client.AreScopesAllowed(requestedScopes) {
		return nil, ErrInvalidScope
	}
	
	// Create authorization code
	var authCode *models.AuthorizationCode
	if req.CodeChallenge != "" {
		// PKCE flow
		authCode, err = models.NewAuthorizationCodeWithPKCE(
			client.ClientID, userID, req.RedirectURI, requestedScopes,
			req.State, req.CodeChallenge, req.CodeChallengeMethod,
		)
	} else {
		// Standard flow
		authCode, err = models.NewAuthorizationCode(
			client.ClientID, userID, req.RedirectURI, requestedScopes, req.State,
		)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization code: %w", err)
	}
	
	// Store authorization code
	if err := s.repo.CreateAuthorizationCode(ctx, authCode); err != nil {
		return nil, fmt.Errorf("failed to store authorization code: %w", err)
	}
	
	return &AuthorizeResponse{
		Code:  authCode.GetPlainCode(),
		State: req.State,
	}, nil
}

// Token handles the OAuth2 token request
func (s *OAuth2Service) Token(ctx context.Context, req *TokenRequest) (*models.TokenResponse, error) {
	switch req.GrantType {
	case models.GrantTypeAuthorizationCode:
		return s.handleAuthorizationCodeGrant(ctx, req)
	case models.GrantTypeRefreshToken:
		return s.handleRefreshTokenGrant(ctx, req)
	case models.GrantTypeClientCredentials:
		return s.handleClientCredentialsGrant(ctx, req)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

// handleAuthorizationCodeGrant processes authorization code grant requests
func (s *OAuth2Service) handleAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*models.TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	
	// Check if client supports this grant type
	if !client.IsGrantTypeAllowed(models.GrantTypeAuthorizationCode) {
		return nil, ErrUnsupportedGrantType
	}
	
	// Hash the authorization code to find it in database
	hasher := sha256.New()
	hasher.Write([]byte(req.Code))
	codeHash := hex.EncodeToString(hasher.Sum(nil))
	
	// Get authorization code
	authCode, err := s.repo.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	
	// Validate authorization code
	if err := authCode.IsValid(req.Code, req.CodeVerifier); err != nil {
		return nil, ErrInvalidGrant
	}
	
	// Verify client and redirect URI match
	if authCode.ClientID != client.ClientID || authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidGrant
	}
	
	// Mark code as used
	if err := s.repo.MarkAuthorizationCodeAsUsed(ctx, codeHash); err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}
	
	// Create access token
	accessToken, err := models.NewAccessToken(client.ClientID, authCode.UserID, authCode.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}
	
	if err := s.repo.CreateAccessToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}
	
	// Create refresh token
	refreshToken, err := models.NewRefreshToken(accessToken.ID, client.ClientID, authCode.UserID, authCode.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}
	
	if err := s.repo.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}
	
	return accessToken.ToTokenResponse(refreshToken.GetPlainToken()), nil
}

// handleRefreshTokenGrant processes refresh token grant requests
func (s *OAuth2Service) handleRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*models.TokenResponse, error) {
	// Validate client
	client, err := s.ValidateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	
	// Check if client supports this grant type
	if !client.IsGrantTypeAllowed(models.GrantTypeRefreshToken) {
		return nil, ErrUnsupportedGrantType
	}
	
	// Hash refresh token to find it in database
	hasher := sha256.New()
	hasher.Write([]byte(req.RefreshToken))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))
	
	// Get refresh token
	refreshToken, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	
	// Validate refresh token
	if err := refreshToken.IsValid(req.RefreshToken); err != nil {
		return nil, ErrInvalidGrant
	}
	
	// Verify client matches
	if refreshToken.ClientID != client.ClientID {
		return nil, ErrInvalidGrant
	}
	
	// Parse requested scopes (must be subset of original scopes)
	requestedScopes := refreshToken.Scopes
	if req.Scope != "" {
		requestedScopes = parseScopes(req.Scope)
		if !hasAllScopes(refreshToken.Scopes, requestedScopes) {
			return nil, ErrInvalidScope
		}
	}
	
	// Revoke old access token
	if err := s.repo.RevokeAccessToken(ctx, refreshToken.AccessTokenID); err != nil {
		return nil, fmt.Errorf("failed to revoke old access token: %w", err)
	}
	
	// Create new access token
	accessToken, err := models.NewAccessToken(client.ClientID, refreshToken.UserID, requestedScopes)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}
	
	if err := s.repo.CreateAccessToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}
	
	// Update refresh token last used
	if err := s.repo.UpdateRefreshTokenLastUsed(ctx, tokenHash); err != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", err)
	}
	
	return accessToken.ToTokenResponse(refreshToken.GetPlainToken()), nil
}

// handleClientCredentialsGrant processes client credentials grant requests
func (s *OAuth2Service) handleClientCredentialsGrant(ctx context.Context, req *TokenRequest) (*models.TokenResponse, error) {
	// Validate client (must be confidential)
	client, err := s.ValidateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, err
	}
	
	// Public clients cannot use client credentials grant
	if client.IsPublic {
		return nil, ErrUnsupportedGrantType
	}
	
	// Check if client supports this grant type
	if !client.IsGrantTypeAllowed(models.GrantTypeClientCredentials) {
		return nil, ErrUnsupportedGrantType
	}
	
	// Parse and validate scopes
	requestedScopes := parseScopes(req.Scope)
	if len(requestedScopes) == 0 {
		return nil, ErrInvalidScope
	}
	
	if !client.AreScopesAllowed(requestedScopes) {
		return nil, ErrInvalidScope
	}
	
	// Create access token (no user ID for client credentials)
	accessToken, err := models.NewAccessToken(client.ClientID, client.UserID, requestedScopes)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}
	
	if err := s.repo.CreateAccessToken(ctx, accessToken); err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}
	
	// Client credentials grant doesn't include refresh token
	return accessToken.ToTokenResponse(""), nil
}

// Token Validation

// ValidateAccessToken validates an access token and returns token information
func (s *OAuth2Service) ValidateAccessToken(ctx context.Context, accessToken string) (*models.OAuth2AccessToken, error) {
	// Hash token to find it in database
	hasher := sha256.New()
	hasher.Write([]byte(accessToken))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))
	
	// Get token from database
	token, err := s.repo.GetAccessTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrTokenNotFound
	}
	
	// Validate token
	if err := token.IsValid(accessToken); err != nil {
		return nil, err
	}
	
	// Update last used timestamp
	if err := s.repo.UpdateAccessTokenLastUsed(ctx, tokenHash); err != nil {
		// Log error but don't fail validation
		// This is a non-critical operation
	}
	
	return token, nil
}

// Revoke revokes an access token or refresh token
func (s *OAuth2Service) Revoke(ctx context.Context, token, clientID, clientSecret string) error {
	// Validate client
	client, err := s.ValidateClient(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}
	
	// Hash token
	hasher := sha256.New()
	hasher.Write([]byte(token))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))
	
	// Try to revoke as access token first
	accessToken, err := s.repo.GetAccessTokenByHash(ctx, tokenHash)
	if err == nil && accessToken.ClientID == client.ClientID {
		if err := s.repo.RevokeAccessToken(ctx, tokenHash); err != nil {
			return fmt.Errorf("failed to revoke access token: %w", err)
		}
		// Also revoke associated refresh tokens
		if err := s.repo.RevokeRefreshTokensByAccessTokenID(ctx, accessToken.ID); err != nil {
			return fmt.Errorf("failed to revoke refresh tokens: %w", err)
		}
		return nil
	}
	
	// Try to revoke as refresh token
	refreshToken, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err == nil && refreshToken.ClientID == client.ClientID {
		return s.repo.RevokeRefreshToken(ctx, tokenHash)
	}
	
	// Token not found or doesn't belong to client
	return ErrTokenNotFound
}

// Cleanup removes expired tokens and authorization codes
func (s *OAuth2Service) Cleanup(ctx context.Context) error {
	if _, err := s.repo.CleanupExpiredAuthorizationCodes(ctx); err != nil {
		return fmt.Errorf("failed to cleanup authorization codes: %w", err)
	}
	
	if _, err := s.repo.CleanupExpiredAccessTokens(ctx); err != nil {
		return fmt.Errorf("failed to cleanup access tokens: %w", err)
	}
	
	if _, err := s.repo.CleanupExpiredRefreshTokens(ctx); err != nil {
		return fmt.Errorf("failed to cleanup refresh tokens: %w", err)
	}
	
	return nil
}

// Helper functions

func parseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	
	scopes := strings.Split(scopeString, " ")
	var result []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			result = append(result, scope)
		}
	}
	return result
}

func hasAllScopes(available, requested []string) bool {
	availableSet := make(map[string]bool)
	for _, scope := range available {
		availableSet[scope] = true
	}
	
	for _, scope := range requested {
		if !availableSet[scope] {
			return false
		}
	}
	return true
}

func buildRedirectURI(baseURI, code, state string, err error) string {
	u, parseErr := url.Parse(baseURI)
	if parseErr != nil {
		return baseURI
	}
	
	query := u.Query()
	if err != nil {
		query.Set("error", err.Error())
	} else {
		query.Set("code", code)
	}
	
	if state != "" {
		query.Set("state", state)
	}
	
	u.RawQuery = query.Encode()
	return u.String()
}