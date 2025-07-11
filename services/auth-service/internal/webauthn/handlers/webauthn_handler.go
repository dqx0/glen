package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// WebAuthnHandler is the main handler that combines all WebAuthn endpoints
type WebAuthnHandler struct {
	registrationHandler   *RegistrationHandler
	authenticationHandler *AuthenticationHandler
	managementHandler     *ManagementHandler
}

// NewWebAuthnHandler creates a new main WebAuthn handler
func NewWebAuthnHandler(webAuthnService service.WebAuthnService, jwtConfig *middleware.JWTConfig) *WebAuthnHandler {
	return &WebAuthnHandler{
		registrationHandler:   NewRegistrationHandler(webAuthnService),
		authenticationHandler: NewAuthenticationHandler(webAuthnService, jwtConfig),
		managementHandler:     NewManagementHandler(webAuthnService, jwtConfig),
	}
}

// RegisterRoutes registers all WebAuthn routes
func (h *WebAuthnHandler) RegisterRoutes(r chi.Router) {
	// Register sub-handlers without adding middleware (already added in main)
	h.registrationHandler.RegisterRoutes(r)
	h.authenticationHandler.RegisterRoutes(r)
	h.managementHandler.RegisterRoutes(r)
	
	// Health check endpoint
	r.Get("/webauthn/health", h.HealthCheck)
}

// HealthCheck provides a health check endpoint for WebAuthn services
func (h *WebAuthnHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	response := HealthCheckResponse{
		Status:  "healthy",
		Service: "webauthn",
		Version: "1.0.0",
	}
	
	h.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *WebAuthnHandler) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HealthCheckResponse represents a health check response
type HealthCheckResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

