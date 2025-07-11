package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/dqx0/glen/user-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/user-service/internal/webauthn/models"
	"github.com/dqx0/glen/user-service/internal/webauthn/service"
)

// ManagementHandler handles WebAuthn credential management endpoints
type ManagementHandler struct {
	webAuthnService service.WebAuthnService
	validator       *validator.Validate
	jwtConfig       *middleware.JWTConfig
}

// NewManagementHandler creates a new management handler
func NewManagementHandler(webAuthnService service.WebAuthnService) *ManagementHandler {
	return &ManagementHandler{
		webAuthnService: webAuthnService,
		validator:       validator.New(),
		jwtConfig:       middleware.DefaultJWTConfig(),
	}
}

// NewManagementHandlerWithJWT creates a new management handler with custom JWT config
func NewManagementHandlerWithJWT(webAuthnService service.WebAuthnService, jwtConfig *middleware.JWTConfig) *ManagementHandler {
	return &ManagementHandler{
		webAuthnService: webAuthnService,
		validator:       validator.New(),
		jwtConfig:       jwtConfig,
	}
}

// RegisterRoutes registers the management routes with authentication
func (h *ManagementHandler) RegisterRoutes(r chi.Router) {
	// Current user's credential management routes - require authentication
	r.Route("/webauthn/credentials", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(h.jwtConfig))
		r.Get("/", h.GetMyCredentials)                    // GET /api/v1/webauthn/credentials
		r.Delete("/{credentialID}", h.DeleteMyCredential) // DELETE /api/v1/webauthn/credentials/{credentialID}
	})
	
	// User-specific credential management routes - require authentication and ownership
	r.Route("/webauthn/users/{userID}/credentials", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(h.jwtConfig))
		r.Use(middleware.RequireOwnerOrAdmin("userID"))
		r.Get("/", h.GetUserCredentials)
		r.Delete("/{credentialID}", h.DeleteCredential)
		r.Put("/{credentialID}", h.UpdateCredential)
	})
	
	// Admin routes - require authentication and admin privileges
	r.Route("/webauthn/admin", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(h.jwtConfig))
		r.Use(middleware.RequireAdmin)
		r.Get("/statistics", h.GetStatistics)
		r.Post("/cleanup", h.CleanupExpiredData)
	})
}

// GetMyCredentials handles GET /webauthn/credentials (current user's credentials)
func (h *ManagementHandler) GetMyCredentials(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT token
	userID, ok := middleware.GetUserID(r)
	if !ok {
		writeWebAuthnErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated", "")
		return
	}

	credentials, err := h.webAuthnService.GetUserCredentials(r.Context(), userID)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	// Convert credentials to a format suitable for frontend
	credentialList := make([]CredentialInfo, len(credentials))
	for i, cred := range credentials {
		credentialList[i] = CredentialInfo{
			ID:              cred.ID,
			CredentialID:    base64.URLEncoding.EncodeToString(cred.CredentialID),
			AttestationType: cred.AttestationType,
			Transport:       cred.Transport,
			Flags:           cred.Flags,
			SignCount:       cred.SignCount,
			CloneWarning:    cred.CloneWarning,
			CreatedAt:       cred.CreatedAt.Format(time.RFC3339),
			UpdatedAt:       cred.UpdatedAt.Format(time.RFC3339),
		}
	}

	response := GetMyCredentialsResponse{
		Success:     true,
		Credentials: credentialList,
		Count:       len(credentialList),
		UserID:      userID,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// DeleteMyCredential handles DELETE /webauthn/credentials/{credentialID} (current user's credential)
func (h *ManagementHandler) DeleteMyCredential(w http.ResponseWriter, r *http.Request) {
	// Get user ID from JWT token
	userID, ok := middleware.GetUserID(r)
	if !ok {
		writeWebAuthnErrorResponse(w, http.StatusUnauthorized, "UNAUTHORIZED", "User not authenticated", "")
		return
	}

	credentialID := chi.URLParam(r, "credentialID")
	if credentialID == "" {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Credential ID is required", "")
		return
	}

	// Decode base64 credential ID
	decodedCredentialID, err := base64.URLEncoding.DecodeString(credentialID)
	if err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid credential ID format", err.Error())
		return
	}

	err = h.webAuthnService.DeleteCredential(r.Context(), userID, decodedCredentialID)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"success":   true,
		"message":   "Credential deleted successfully",
		"timestamp": time.Now().Unix(),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetUserCredentials handles GET /webauthn/credentials/{userID}
func (h *ManagementHandler) GetUserCredentials(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	if userID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "User ID is required", "")
		return
	}

	// Authentication and authorization is handled by middleware

	credentials, err := h.webAuthnService.GetUserCredentials(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := GetCredentialsResponse{
		Success:     true,
		Credentials: credentials,
		Count:       len(credentials),
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// DeleteCredential handles DELETE /webauthn/users/{userID}/credentials/{credentialID}
func (h *ManagementHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	credentialID := chi.URLParam(r, "credentialID")
	
	if userID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "User ID is required", "")
		return
	}
	
	if credentialID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Credential ID is required", "")
		return
	}

	// Decode base64 credential ID
	decodedCredentialID, err := base64.URLEncoding.DecodeString(credentialID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid credential ID format", err.Error())
		return
	}

	// Authentication and authorization is handled by middleware
	err = h.webAuthnService.DeleteCredential(r.Context(), userID, decodedCredentialID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := SuccessResponse{
		Success: true,
		Message: "Credential deleted successfully",
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// UpdateCredential handles PUT /webauthn/users/{userID}/credentials/{credentialID}
func (h *ManagementHandler) UpdateCredential(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	credentialID := chi.URLParam(r, "credentialID")
	
	if userID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "User ID is required", "")
		return
	}
	
	if credentialID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Credential ID is required", "")
		return
	}

	var req UpdateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err.Error())
		return
	}

	// Decode base64 credential ID
	decodedCredentialID, err := base64.URLEncoding.DecodeString(credentialID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid credential ID format", err.Error())
		return
	}

	// Authentication and authorization is handled by middleware

	// Get the existing credential first
	credentials, err := h.webAuthnService.GetUserCredentials(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Find the credential to update
	var targetCredential *models.WebAuthnCredential
	for _, cred := range credentials {
		if string(cred.CredentialID) == string(decodedCredentialID) {
			targetCredential = cred
			break
		}
	}

	if targetCredential == nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Credential not found", "")
		return
	}

	// Update allowed fields
	if req.CloneWarning != nil {
		targetCredential.CloneWarning = *req.CloneWarning
	}
	// Add other updatable fields as needed

	err = h.webAuthnService.UpdateCredential(r.Context(), targetCredential)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := SuccessResponse{
		Success: true,
		Message: "Credential updated successfully",
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// GetStatistics handles GET /webauthn/admin/statistics
func (h *ManagementHandler) GetStatistics(w http.ResponseWriter, r *http.Request) {
	// Admin authentication and authorization is handled by middleware

	statistics, err := h.webAuthnService.GetCredentialStatistics(r.Context())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := StatisticsResponse{
		Success:    true,
		Statistics: statistics,
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// CleanupExpiredData handles POST /webauthn/admin/cleanup
func (h *ManagementHandler) CleanupExpiredData(w http.ResponseWriter, r *http.Request) {
	// Admin authentication and authorization is handled by middleware

	err := h.webAuthnService.CleanupExpiredData(r.Context())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := SuccessResponse{
		Success: true,
		Message: "Expired data cleaned up successfully",
	}

	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods for response handling

func (h *ManagementHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *ManagementHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message, details string) {
	errorResponse := ErrorResponse{
		Error:   message,
		Details: details,
		Code:    statusCode,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		http.Error(w, message, statusCode)
	}
}

func (h *ManagementHandler) handleServiceError(w http.ResponseWriter, err error) {
	if serviceErr, ok := err.(*service.ServiceError); ok {
		statusCode := serviceErr.HTTPStatusCode()
		h.writeErrorResponse(w, statusCode, serviceErr.Message, serviceErr.Details)
		return
	}
	
	h.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", err.Error())
}

// Request/Response types

// UpdateCredentialRequest represents a request to update a credential
type UpdateCredentialRequest struct {
	CloneWarning *bool `json:"clone_warning,omitempty"`
	// Add other updatable fields as needed
}

// CredentialInfo represents credential information for frontend
type CredentialInfo struct {
	ID              string                            `json:"id"`
	CredentialID    string                            `json:"credential_id"` // base64 encoded
	AttestationType string                            `json:"attestation_type"`
	Transport       []models.AuthenticatorTransport  `json:"transport"`
	Flags           models.AuthenticatorFlags        `json:"flags"`
	SignCount       uint32                            `json:"sign_count"`
	CloneWarning    bool                              `json:"clone_warning"`
	CreatedAt       string                            `json:"created_at"`
	UpdatedAt       string                            `json:"updated_at"`
}

// GetMyCredentialsResponse represents the response for getting current user's credentials
type GetMyCredentialsResponse struct {
	Success     bool             `json:"success"`
	Credentials []CredentialInfo `json:"credentials"`
	Count       int              `json:"count"`
	UserID      string           `json:"user_id"`
}

// GetCredentialsResponse represents the response for getting user credentials
type GetCredentialsResponse struct {
	Success     bool                         `json:"success"`
	Credentials []*models.WebAuthnCredential `json:"credentials"`
	Count       int                          `json:"count"`
}

// StatisticsResponse represents the response for getting statistics
type StatisticsResponse struct {
	Success    bool                      `json:"success"`
	Statistics *service.CredentialStatistics `json:"statistics"`
}

