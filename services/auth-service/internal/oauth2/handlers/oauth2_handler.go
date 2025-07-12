package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/dqx0/glen/auth-service/internal/oauth2/models"
	"github.com/dqx0/glen/auth-service/internal/oauth2/service"
)

// OAuth2ServiceInterface defines the interface for OAuth2 service
type OAuth2ServiceInterface interface {
	CreateClient(ctx context.Context, userID, name, description string, redirectURIs, scopes []string, isPublic bool) (*models.OAuth2Client, error)
	GetClient(ctx context.Context, clientID string) (*models.OAuth2Client, error)
	GetClientsByUserID(ctx context.Context, userID string) ([]*models.OAuth2Client, error)
	DeleteClient(ctx context.Context, clientID, userID string) error
	Authorize(ctx context.Context, userID string, req *service.AuthorizeRequest) (*service.AuthorizeResponse, error)
	Token(ctx context.Context, req *service.TokenRequest) (*models.TokenResponse, error)
	ValidateAccessToken(ctx context.Context, accessToken string) (*models.OAuth2AccessToken, error)
	Revoke(ctx context.Context, token, clientID, clientSecret string) error
	Cleanup(ctx context.Context) error
}

// OAuth2Handler handles OAuth2 authorization server endpoints
type OAuth2Handler struct {
	oauth2Service OAuth2ServiceInterface
}

// NewOAuth2Handler creates a new OAuth2Handler
func NewOAuth2Handler(oauth2Service OAuth2ServiceInterface) *OAuth2Handler {
	return &OAuth2Handler{
		oauth2Service: oauth2Service,
	}
}

// OAuth2ErrorResponse represents an OAuth2 error response
type OAuth2ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// CreateClientRequest represents a request to create an OAuth2 client
type CreateClientRequest struct {
	UserID       string   `json:"user_id"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	IsPublic     bool     `json:"is_public"`
}

// CreateClientResponse represents the response from creating an OAuth2 client
type CreateClientResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	IsPublic     bool     `json:"is_public"`
	CreatedAt    string   `json:"created_at"`
}

// Authorize handles OAuth2 authorization requests
// GET/POST /oauth/authorize
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters (GET) or form data (POST)
	var values url.Values
	if r.Method == http.MethodGet {
		values = r.URL.Query()
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			h.redirectWithError(w, r, "", "", "invalid_request", "Failed to parse form data")
			return
		}
		values = r.Form
	} else {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Extract parameters
	clientID := values.Get("client_id")
	redirectURI := values.Get("redirect_uri")
	responseType := values.Get("response_type")
	scope := values.Get("scope")
	state := values.Get("state")
	codeChallenge := values.Get("code_challenge")
	codeChallengeMethod := values.Get("code_challenge_method")

	// Basic validation
	if clientID == "" || redirectURI == "" || responseType == "" {
		h.redirectWithError(w, r, redirectURI, state, "invalid_request", "Missing required parameters")
		return
	}

	// For now, we'll assume the user is authenticated and get user ID from context or session
	// In a real implementation, this would check user authentication and handle login flow
	userID := h.getUserID(r)
	if userID == "" {
		// Redirect to login page with return URL
		loginURL := h.buildLoginURL(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Create authorization request
	authReq := &service.AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	// Process authorization
	authResp, err := h.oauth2Service.Authorize(r.Context(), userID, authReq)
	if err != nil {
		h.redirectWithError(w, r, redirectURI, state, h.mapServiceErrorToOAuth2Error(err), err.Error())
		return
	}

	// Build redirect URL with authorization code
	redirectURL := h.buildSuccessRedirectURL(redirectURI, authResp.Code, authResp.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Token handles OAuth2 token requests
// POST /oauth/token
func (h *OAuth2Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	// Extract client credentials from Authorization header or form
	clientID, clientSecret := h.extractClientCredentials(r)
	
	// Create token request
	tokenReq := &service.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.FormValue("code_verifier"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
	}

	// Basic validation
	if tokenReq.GrantType == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing grant_type parameter")
		return
	}

	if tokenReq.ClientID == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_client", "Missing client authentication")
		return
	}

	// Process token request
	tokenResp, err := h.oauth2Service.Token(r.Context(), tokenReq)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), h.mapServiceErrorToOAuth2Error(err), err.Error())
		return
	}

	// Return token response
	h.writeJSON(w, http.StatusOK, tokenResp)
}

// Revoke handles OAuth2 token revocation requests
// POST /oauth/revoke
func (h *OAuth2Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	// Extract client credentials
	clientID, clientSecret := h.extractClientCredentials(r)
	token := r.FormValue("token")

	if token == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing token parameter")
		return
	}

	if clientID == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_client", "Missing client authentication")
		return
	}

	// Revoke token
	err := h.oauth2Service.Revoke(r.Context(), token, clientID, clientSecret)
	if err != nil {
		// For revocation, we return success even if token is not found (per RFC)
		if !errors.Is(err, service.ErrTokenNotFound) {
			h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), h.mapServiceErrorToOAuth2Error(err), err.Error())
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// Introspect handles OAuth2 token introspection requests (RFC 7662)
// POST /oauth/introspect
func (h *OAuth2Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Failed to parse form data")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing token parameter")
		return
	}

	// Validate access token
	accessToken, err := h.oauth2Service.ValidateAccessToken(r.Context(), token)
	if err != nil {
		// Return inactive token response
		response := map[string]interface{}{
			"active": false,
		}
		h.writeJSON(w, http.StatusOK, response)
		return
	}

	// Return active token information
	response := map[string]interface{}{
		"active":     true,
		"client_id":  accessToken.ClientID,
		"username":   accessToken.UserID,
		"scope":      strings.Join(accessToken.Scopes, " "),
		"token_type": accessToken.TokenType,
		"exp":        accessToken.ExpiresAt.Unix(),
		"iat":        accessToken.CreatedAt.Unix(),
	}

	h.writeJSON(w, http.StatusOK, response)
}

// CreateClient handles OAuth2 client registration
// POST /oauth/clients
func (h *OAuth2Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	// Validate required fields
	if req.UserID == "" || req.Name == "" || len(req.RedirectURIs) == 0 || len(req.Scopes) == 0 {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing required fields")
		return
	}

	// Create client
	client, err := h.oauth2Service.CreateClient(r.Context(), req.UserID, req.Name, req.Description, req.RedirectURIs, req.Scopes, req.IsPublic)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), "server_error", err.Error())
		return
	}

	// Prepare response
	response := &CreateClientResponse{
		ClientID:     client.ClientID,
		Name:         client.Name,
		Description:  client.Description,
		RedirectURIs: client.RedirectURIs,
		Scopes:       client.Scopes,
		IsPublic:     client.IsPublic,
		CreatedAt:    client.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}

	// Include client secret for confidential clients
	if !client.IsPublic {
		response.ClientSecret = client.GetPlainClientSecret()
	}

	h.writeJSON(w, http.StatusCreated, response)
}

// GetClients handles OAuth2 client listing for a user
// GET /oauth2/clients?user_id=xxx
func (h *OAuth2Handler) GetClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing user_id parameter")
		return
	}

	// Get clients for user
	clients, err := h.oauth2Service.GetClientsByUserID(r.Context(), userID)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), "server_error", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, clients)
}

// GetClient handles OAuth2 client retrieval by client ID
// GET /oauth2/clients/{client_id}
func (h *OAuth2Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Extract client_id from URL path - handle Chi router wildcard
	clientID := strings.TrimPrefix(r.URL.Path, "/api/v1/oauth2/clients/")
	if clientID == "" || clientID == "/api/v1/oauth2/clients/" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing client_id")
		return
	}

	// Get client
	client, err := h.oauth2Service.GetClient(r.Context(), clientID)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), h.mapServiceErrorToOAuth2Error(err), err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, client)
}

// DeleteClient handles OAuth2 client deletion
// DELETE /oauth2/clients/{client_id}
func (h *OAuth2Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Extract client_id from URL path - handle Chi router wildcard
	clientID := strings.TrimPrefix(r.URL.Path, "/api/v1/oauth2/clients/")
	if clientID == "" || clientID == "/api/v1/oauth2/clients/" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing client_id")
		return
	}

	// Get user ID from context or query parameter (in a real implementation, this would come from authentication)
	userID := h.getUserID(r)
	if userID == "" {
		h.writeOAuth2Error(w, http.StatusUnauthorized, "unauthorized", "User authentication required")
		return
	}

	// Delete client
	err := h.oauth2Service.DeleteClient(r.Context(), clientID, userID)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), h.mapServiceErrorToOAuth2Error(err), err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper methods

func (h *OAuth2Handler) getUserID(r *http.Request) string {
	// This is a placeholder implementation
	// In a real application, you would:
	// 1. Check for a valid session
	// 2. Validate JWT token
	// 3. Extract user ID from authentication context
	
	// For demo purposes, check for a user_id header
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	
	// Or check for a test parameter (only for development)
	if userID := r.URL.Query().Get("test_user_id"); userID != "" {
		return userID
	}
	
	return ""
}

func (h *OAuth2Handler) buildLoginURL(returnURL string) string {
	// This should redirect to your application's login page
	// The login page should handle authentication and redirect back to the OAuth authorization endpoint
	loginURL := "/auth/login?redirect_uri=" + url.QueryEscape(returnURL)
	return loginURL
}

func (h *OAuth2Handler) extractClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// Try Authorization header first (HTTP Basic Auth)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			// Parse Basic Auth
			// This is a simplified implementation
			// In production, you should properly decode the base64 credentials
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
	}
	
	// Fallback to form parameters
	if clientID == "" {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	
	return clientID, clientSecret
}

func (h *OAuth2Handler) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, errorDescription string) {
	if redirectURI == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, errorCode, errorDescription)
		return
	}
	
	redirectURL := h.buildErrorRedirectURL(redirectURI, state, errorCode, errorDescription)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *OAuth2Handler) buildSuccessRedirectURL(baseURI, code, state string) string {
	u, err := url.Parse(baseURI)
	if err != nil {
		return baseURI
	}
	
	query := u.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	
	u.RawQuery = query.Encode()
	return u.String()
}

func (h *OAuth2Handler) buildErrorRedirectURL(baseURI, state, errorCode, errorDescription string) string {
	u, err := url.Parse(baseURI)
	if err != nil {
		return baseURI
	}
	
	query := u.Query()
	query.Set("error", errorCode)
	if errorDescription != "" {
		query.Set("error_description", errorDescription)
	}
	if state != "" {
		query.Set("state", state)
	}
	
	u.RawQuery = query.Encode()
	return u.String()
}

func (h *OAuth2Handler) mapServiceErrorToOAuth2Error(err error) string {
	switch {
	case errors.Is(err, service.ErrInvalidClient):
		return "invalid_client"
	case errors.Is(err, service.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, service.ErrInvalidGrant):
		return "invalid_grant"
	case errors.Is(err, service.ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, service.ErrUnsupportedGrantType):
		return "unsupported_grant_type"
	case errors.Is(err, service.ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, service.ErrAccessDenied):
		return "access_denied"
	default:
		return "server_error"
	}
}

func (h *OAuth2Handler) mapServiceErrorToHTTPStatus(err error) int {
	switch {
	case errors.Is(err, service.ErrInvalidClient),
		 errors.Is(err, service.ErrInvalidClientSecret):
		return http.StatusUnauthorized
	case errors.Is(err, service.ErrInvalidRequest),
		 errors.Is(err, service.ErrInvalidGrant),
		 errors.Is(err, service.ErrInvalidScope),
		 errors.Is(err, service.ErrUnsupportedGrantType),
		 errors.Is(err, service.ErrUnsupportedResponseType):
		return http.StatusBadRequest
	case errors.Is(err, service.ErrAccessDenied):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func (h *OAuth2Handler) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}

func (h *OAuth2Handler) writeOAuth2Error(w http.ResponseWriter, statusCode int, errorCode, errorDescription string) {
	response := OAuth2ErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	}
	h.writeJSON(w, statusCode, response)
}