package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	"github.com/dqx0/glen/user-service/internal/webauthn/service"
)

// RegistrationHandler handles WebAuthn registration endpoints
type RegistrationHandler struct {
	webAuthnService service.WebAuthnService
	validator       *validator.Validate
}

// NewRegistrationHandler creates a new registration handler
func NewRegistrationHandler(webAuthnService service.WebAuthnService) *RegistrationHandler {
	return &RegistrationHandler{
		webAuthnService: webAuthnService,
		validator:       validator.New(),
	}
}

// RegisterRoutes registers the registration routes
func (h *RegistrationHandler) RegisterRoutes(r chi.Router) {
	r.Route("/webauthn/register", func(r chi.Router) {
		r.Post("/start", h.StartRegistration)
		r.Post("/finish", h.FinishRegistration)
	})
}

// StartRegistration handles POST /webauthn/register/start
func (h *RegistrationHandler) StartRegistration(w http.ResponseWriter, r *http.Request) {
	var req service.RegistrationStartRequest
	
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", err.Error())
		return
	}

	// Sanitize user input
	req.Username = sanitizeUserInput(req.Username)
	req.DisplayName = sanitizeUserInput(req.DisplayName)

	// Validate request
	if err := h.validator.Struct(&req); err != nil {
		writeWebAuthnErrorResponse(w, http.StatusBadRequest, "VALIDATION_ERROR", "Validation failed", err.Error())
		return
	}

	// Call service
	response, err := h.webAuthnService.BeginRegistration(r.Context(), &req)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	// Convert to base64 format for client compatibility
	base64Response := map[string]interface{}{
		"sessionId": response.SessionID,
		"options":   convertCreationOptionsToBase64(response.CreationOptions),
		"expiresAt": response.ExpiresAt.Format(time.RFC3339),
	}

	// Write success response
	h.writeJSONResponse(w, http.StatusOK, base64Response)
}

// FinishRegistration handles POST /webauthn/register/finish
func (h *RegistrationHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// Parse request with proper base64 handling
	req, err := parseRegistrationFinishRequest(r)
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
	result, err := h.webAuthnService.FinishRegistration(r.Context(), req)
	if err != nil {
		handleWebAuthnServiceError(w, err)
		return
	}

	// Check if registration was successful
	if !result.Success {
		if result.Error != nil {
			statusCode := result.Error.HTTPStatusCode()
			writeWebAuthnErrorResponse(w, statusCode, string(result.Error.Type), result.Error.Message, result.Error.Details)
			return
		}
		writeWebAuthnErrorResponse(w, http.StatusInternalServerError, "REGISTRATION_FAILED", "Registration failed", "Unknown error")
		return
	}

	// Create enhanced response
	response := map[string]interface{}{
		"success":       result.Success,
		"credentialId":  result.CredentialID,
		"warnings":      result.Warnings,
		"timestamp":     time.Now().Unix(),
	}

	// Write success response
	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods for response handling

func (h *RegistrationHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// If we can't encode the response, log the error and write a generic error
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (h *RegistrationHandler) writeErrorResponse(w http.ResponseWriter, statusCode int, message, details string) {
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

func (h *RegistrationHandler) handleServiceError(w http.ResponseWriter, err error) {
	if serviceErr, ok := err.(*service.ServiceError); ok {
		statusCode := serviceErr.HTTPStatusCode()
		h.writeErrorResponse(w, statusCode, serviceErr.Message, serviceErr.Details)
		return
	}
	
	// Generic error handling
	h.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", err.Error())
}

// ErrorResponse represents an API error response
