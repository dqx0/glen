package handlers

import (
	"encoding/json"
	"net/http"

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
	// Credential management routes - require authentication and ownership
	r.Route("/webauthn/credentials", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(h.jwtConfig))
		r.Use(middleware.RequireOwnerOrAdmin("userID"))
		r.Get("/{userID}", h.GetUserCredentials)
		r.Delete("/{userID}/{credentialID}", h.DeleteCredential)
		r.Put("/{userID}/{credentialID}", h.UpdateCredential)
	})
	
	// Admin routes - require authentication and admin privileges
	r.Route("/webauthn/admin", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(h.jwtConfig))
		r.Use(middleware.RequireAdmin)
		r.Get("/statistics", h.GetStatistics)
		r.Post("/cleanup", h.CleanupExpiredData)
	})
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

// DeleteCredential handles DELETE /webauthn/credentials/{userID}/{credentialID}
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

	// Authentication and authorization is handled by middleware

	err := h.webAuthnService.DeleteCredential(r.Context(), userID, []byte(credentialID))
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

// UpdateCredential handles PUT /webauthn/credentials/{userID}/{credentialID}
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
		if string(cred.CredentialID) == credentialID {
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

