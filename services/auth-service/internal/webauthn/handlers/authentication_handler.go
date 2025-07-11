package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// AuthenticationHandler handles WebAuthn authentication endpoints
type AuthenticationHandler struct {
	webAuthnService service.WebAuthnService
	validator       *validator.Validate
	jwtConfig       *middleware.JWTConfig
}

// NewAuthenticationHandler creates a new authentication handler
func NewAuthenticationHandler(webAuthnService service.WebAuthnService, jwtConfig *middleware.JWTConfig) *AuthenticationHandler {
	return &AuthenticationHandler{
		webAuthnService: webAuthnService,
		validator:       validator.New(),
		jwtConfig:       jwtConfig,
	}
}

// NewAuthenticationHandlerWithJWT creates a new authentication handler with custom JWT config
func NewAuthenticationHandlerWithJWT(webAuthnService service.WebAuthnService, jwtConfig *middleware.JWTConfig) *AuthenticationHandler {
	return &AuthenticationHandler{
		webAuthnService: webAuthnService,
		validator:       validator.New(),
		jwtConfig:       jwtConfig,
	}
}

// RegisterRoutes registers the authentication routes
func (h *AuthenticationHandler) RegisterRoutes(r chi.Router) {
	r.Route("/webauthn/authenticate", func(r chi.Router) {
		r.Post("/start", h.StartAuthentication)
		r.Post("/finish", h.FinishAuthentication)
	})
}

// StartAuthentication handles POST /webauthn/authenticate/start
func (h *AuthenticationHandler) StartAuthentication(w http.ResponseWriter, r *http.Request) {
	var req service.AuthenticationStartRequest
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", err.Error())
		return
	}

	// Sanitize user input
	req.UserIdentifier = sanitizeUserInput(req.UserIdentifier)

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Validation failed", err.Error())
		return
	}

	// Call service
	response, err := h.webAuthnService.BeginAuthentication(r.Context(), &req)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	// Convert to base64 format for client compatibility
	base64Response := map[string]interface{}{
		"sessionId": response.SessionID,
		"options":   convertRequestOptionsToBase64(response.RequestOptions),
		"expiresAt": response.ExpiresAt.Format(time.RFC3339),
	}

	// Write success response
	h.writeJSONResponse(w, http.StatusOK, base64Response)
}

// FinishAuthentication handles POST /webauthn/authenticate/finish
func (h *AuthenticationHandler) FinishAuthentication(w http.ResponseWriter, r *http.Request) {
	// Parse request with proper base64 handling
	req, err := parseAuthenticationFinishRequest(r)
	if err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format", err.Error())
		return
	}

	// Validate request structure
	if err := h.validator.Struct(req); err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Validation failed", err.Error())
		return
	}

	// Call service
	result, err := h.webAuthnService.FinishAuthentication(r.Context(), req)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	// Check if authentication was successful
	if !result.Success {
		if result.Error != nil {
			statusCode := result.Error.HTTPStatusCode()
			writeWebAuthnErrorResponse(w, statusCode, string(result.Error.Type), result.Error.Message, result.Error.Details)
			return
		}
		writeWebAuthnErrorResponse(w, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "Authentication failed", "Unknown error")
		return
	}

	// For WebAuthn authentication, we'll return success without JWT generation
	// The frontend will handle the session or the user can use the /auth/login endpoint for JWT tokens
	// This maintains separation of concerns between WebAuthn authentication and JWT token generation

	response := AuthenticationSuccessResponse{
		Success:            result.Success,
		UserID:             result.UserID,
		CredentialID:       result.CredentialID,
		AuthenticationTime: result.AuthenticationTime.Format(time.RFC3339),
		Warnings:           result.Warnings,
		SignCount:          result.SignCount,
		Timestamp:          time.Now().Unix(),
	}

	// Write success response
	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods for response handling

func (h *AuthenticationHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If we can't encode the response, log the error and write a generic error
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthenticationHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message, details string) {
	errorResponse := ErrorResponse{
		Error:   message,
		Details: details,
		Code:    statusCode,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		// Fallback to plain text error
		http.Error(w, message, statusCode)
	}
}

func (h *AuthenticationHandler) handleServiceError(w http.ResponseWriter, err error) {
	if serviceErr, ok := err.(*service.ServiceError); ok {
		statusCode := serviceErr.HTTPStatusCode()
		h.writeErrorResponse(w, statusCode, serviceErr.Message, serviceErr.Details)
		return
	}
	
	// Generic error handling
	h.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", err.Error())
}

// AuthenticationSuccessResponse represents a successful authentication response
type AuthenticationSuccessResponse struct {
	Success            bool     `json:"success"`
	UserID             string   `json:"user_id"`
	CredentialID       string   `json:"credential_id"`
	AuthenticationTime string   `json:"authentication_time"`
	Warnings           []string `json:"warnings,omitempty"`
	Token              string   `json:"token,omitempty"` // JWT token for session management
	SignCount          uint32   `json:"sign_count,omitempty"`
	Timestamp          int64    `json:"timestamp"`
}

