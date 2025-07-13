package handlers

import (
	"context"
	"encoding/base64"
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

// AuthorizeRequest represents the authorization request from API Gateway
type AuthorizeAPIRequest struct {
	UserID              string `json:"user_id"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
}

// AuthorizeResponse represents the authorization response
type AuthorizeAPIResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// Authorize handles OAuth2 authorization requests from API Gateway
// POST /oauth/authorize
func (h *OAuth2Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuth2Error(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	var req AuthorizeAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Invalid JSON")
		return
	}

	// Basic validation
	if req.UserID == "" || req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
		h.writeOAuth2Error(w, http.StatusBadRequest, "invalid_request", "Missing required parameters")
		return
	}

	log.Printf("OAuth2 Auth Service: Processing authorization for user: %s, client: %s", req.UserID, req.ClientID)

	// Create service authorization request
	authReq := &service.AuthorizeRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	// Process authorization through service
	authResp, err := h.oauth2Service.Authorize(r.Context(), req.UserID, authReq)
	if err != nil {
		h.writeOAuth2Error(w, h.mapServiceErrorToHTTPStatus(err), h.mapServiceErrorToOAuth2Error(err), err.Error())
		return
	}

	// Return JSON response to API Gateway
	response := &AuthorizeAPIResponse{
		Code:  authResp.Code,
		State: authResp.State,
	}

	log.Printf("OAuth2 Auth Service: Authorization successful, returning code: %s", authResp.Code)
	h.writeJSON(w, http.StatusOK, response)
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
	
	// Check for session-based authentication (standard OAuth2 approach)
	// In a real OAuth2 implementation, you would check:
	// 1. HTTP session cookies
	// 2. Server-side session storage
	// 3. JWT tokens in secure cookies
	
	// Log all cookies for debugging
	log.Printf("OAuth2 getUserID: All cookies: %v", r.Cookies())
	
	// For this demo, we'll check for a session token in cookies
	if cookie, err := r.Cookie("glen_session"); err == nil && cookie.Value != "" {
		log.Printf("OAuth2 getUserID: Found glen_session cookie: %s", cookie.Value[:20]+"...")
		// Extract user ID from session token
		if userID := h.extractUserIDFromSession(cookie.Value); userID != "" {
			log.Printf("OAuth2 getUserID: Extracted user ID from session: %s", userID)
			return userID
		}
	} else {
		log.Printf("OAuth2 getUserID: No glen_session cookie found, error: %v", err)
	}
	
	// Fallback: Check for X-User-ID header (for API Gateway forwarding)
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	
	
	return ""
}

func (h *OAuth2Handler) showLoginForm(w http.ResponseWriter, r *http.Request, clientID, redirectURI, responseType, scope, state, codeChallenge, codeChallengeMethod string) {
	// Generate a simple OAuth2 login form that will handle authentication
	// and redirect back to the OAuth2 flow
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Glen ID Platform - OAuth2 Login</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        .btn:hover { background: #0056b3; }
        .title { text-align: center; margin-bottom: 30px; color: #333; }
        .oauth-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h2 class="title">Glen ID Platform</h2>
    <div class="oauth-info">
        <p><strong>Application:</strong> ` + clientID + `</p>
        <p><strong>Permissions:</strong> ` + scope + `</p>
    </div>
    <form method="POST" action="/api/v1/oauth2/authorize">
        <input type="hidden" name="client_id" value="` + clientID + `">
        <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
        <input type="hidden" name="response_type" value="` + responseType + `">
        <input type="hidden" name="scope" value="` + scope + `">
        <input type="hidden" name="state" value="` + state + `">
        <input type="hidden" name="code_challenge" value="` + codeChallenge + `">
        <input type="hidden" name="code_challenge_method" value="` + codeChallengeMethod + `">
        
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        
        <button type="submit" class="btn">Login and Authorize</button>
    </form>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (h *OAuth2Handler) showConsentScreen(w http.ResponseWriter, r *http.Request, clientID, redirectURI, responseType, scope, state, codeChallenge, codeChallengeMethod, userID string) {
	// Generate OAuth2 consent screen (standard OAuth2 UX)
	scopeList := strings.Split(scope, " ")
	scopeDescriptions := map[string]string{
		"read":    "プロフィール情報の読み取り",
		"write":   "プロフィール情報の更新", 
		"profile": "基本プロフィール情報へのアクセス",
		"email":   "メールアドレスへのアクセス",
	}
	
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Glen ID Platform - Authorization</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 100px auto; padding: 20px; background: #f5f5f5; }
        .consent-card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .title { text-align: center; margin-bottom: 30px; color: #333; }
        .app-info { background: #e3f2fd; padding: 20px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid #2196f3; }
        .permissions { margin: 20px 0; }
        .permission-item { padding: 10px 0; border-bottom: 1px solid #eee; }
        .permission-item:last-child { border-bottom: none; }
        .buttons { display: flex; gap: 10px; margin-top: 30px; }
        .btn { padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; flex: 1; }
        .btn-approve { background: #4caf50; color: white; }
        .btn-approve:hover { background: #45a049; }
        .btn-deny { background: #f44336; color: white; }
        .btn-deny:hover { background: #da190b; }
        .user-info { text-align: center; margin-bottom: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="consent-card">
        <h2 class="title">🔐 Glen ID Platform</h2>
        
        <div class="user-info">
            Logged in as: <strong>` + userID + `</strong>
        </div>
        
        <div class="app-info">
            <h3>Authorization Request</h3>
            <p><strong>Application:</strong> ` + clientID + `</p>
            <p>This application is requesting access to your account.</p>
        </div>
        
        <div class="permissions">
            <h4>Requested Permissions:</h4>`
	
	for _, s := range scopeList {
		desc, exists := scopeDescriptions[s]
		if !exists {
			desc = s
		}
		html += `
            <div class="permission-item">
                <strong>` + s + `:</strong> ` + desc + `
            </div>`
	}
	
	html += `
        </div>
        
        <div class="buttons">
            <form method="POST" style="flex: 1;" onsubmit="this.querySelector('button').disabled=true;">
                <input type="hidden" name="client_id" value="` + clientID + `">
                <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
                <input type="hidden" name="response_type" value="` + responseType + `">
                <input type="hidden" name="scope" value="` + scope + `">
                <input type="hidden" name="state" value="` + state + `">
                <input type="hidden" name="code_challenge" value="` + codeChallenge + `">
                <input type="hidden" name="code_challenge_method" value="` + codeChallengeMethod + `">
                <input type="hidden" name="consent" value="approve">
                <button type="submit" class="btn btn-approve">Allow</button>
            </form>
            
            <form method="POST" style="flex: 1;" onsubmit="this.querySelector('button').disabled=true;">
                <input type="hidden" name="client_id" value="` + clientID + `">
                <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
                <input type="hidden" name="state" value="` + state + `">
                <input type="hidden" name="consent" value="deny">
                <button type="submit" class="btn btn-deny">Deny</button>
            </form>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func (h *OAuth2Handler) authenticateUser(w http.ResponseWriter, r *http.Request, username, password string) bool {
	// This is a simplified authentication for demo purposes
	// In production, you would:
	// 1. Validate credentials against user database
	// 2. Check password hash
	// 3. Handle account lockouts, etc.
	
	log.Printf("OAuth2 authenticateUser: Attempting authentication for user: %s", username)
	
	// For demo: accept any non-empty username/password
	if username != "" && password != "" {
		// Generate a mock user ID (in production, get from database)
		userID := "user_" + username
		
		// Create session token (simplified - use the username as token for demo)
		sessionToken := "session_" + userID + "_" + username
		
		// Set session cookie
		sessionCookie := &http.Cookie{
			Name:     "glen_session",
			Value:    sessionToken,
			// No Domain set - allows sharing across localhost ports
			Path:     "/",
			HttpOnly: false, // Set to false for development debugging
			Secure:   false, // Set to true in production with HTTPS  
			SameSite: http.SameSiteLaxMode, // Use Lax for better browser compatibility
			MaxAge:   3600, // 1 hour
		}
		http.SetCookie(w, sessionCookie)
		
		log.Printf("OAuth2 authenticateUser: Authentication successful for user: %s, userID: %s", username, userID)
		return true
	}
	
	log.Printf("OAuth2 authenticateUser: Authentication failed for user: %s", username)
	return false
}

func (h *OAuth2Handler) extractUserIDFromSession(sessionToken string) string {
	// This is a simplified session token parsing for demo purposes
	// In production, you would:
	// 1. Validate the session token signature
	// 2. Check session expiration
	// 3. Look up session in server-side storage (Redis, database, etc.)
	
	log.Printf("OAuth2 extractUserIDFromSession: Parsing session token: %s", sessionToken)
	
	// Parse our simple session token format: "session_user_username_username"
	if strings.HasPrefix(sessionToken, "session_user_") {
		parts := strings.Split(sessionToken, "_")
		if len(parts) >= 3 {
			userID := "user_" + parts[2] // Extract username part
			log.Printf("OAuth2 extractUserIDFromSession: Extracted user ID: %s", userID)
			return userID
		}
	}
	
	// Fallback: try JWT format for backward compatibility
	if strings.Contains(sessionToken, ".") {
		return h.extractUserIDFromJWT(sessionToken)
	}
	
	log.Printf("OAuth2 extractUserIDFromSession: Could not parse session token")
	return ""
}

func (h *OAuth2Handler) extractUserIDFromJWT(token string) string {
	// This is a simplified JWT parsing for demo purposes
	// In production, you should properly validate the JWT signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	
	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	
	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	
	// Extract user_id from claims
	if userID, ok := claims["user_id"].(string); ok {
		return userID
	}
	
	return ""
}

func (h *OAuth2Handler) buildLoginURL(returnURL string) string {
	// This should redirect to your application's login page
	// The login page should handle authentication and redirect back to the OAuth authorization endpoint
	// Build the full return URL for API Gateway (centralized access)
	fullReturnURL := "http://localhost:8080" + returnURL
	loginURL := "http://localhost:5173/login?redirect_uri=" + url.QueryEscape(fullReturnURL)
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