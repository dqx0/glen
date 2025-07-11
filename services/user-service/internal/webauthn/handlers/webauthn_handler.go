package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/dqx0/glen/user-service/internal/webauthn/service"
)

// WebAuthnHandler is the main handler that combines all WebAuthn endpoints
type WebAuthnHandler struct {
	registrationHandler   *RegistrationHandler
	authenticationHandler *AuthenticationHandler
	managementHandler     *ManagementHandler
}

// NewWebAuthnHandler creates a new main WebAuthn handler
func NewWebAuthnHandler(webAuthnService service.WebAuthnService) *WebAuthnHandler {
	return &WebAuthnHandler{
		registrationHandler:   NewRegistrationHandler(webAuthnService),
		authenticationHandler: NewAuthenticationHandler(webAuthnService),
		managementHandler:     NewManagementHandler(webAuthnService),
	}
}

// RegisterRoutes registers all WebAuthn routes
func (h *WebAuthnHandler) RegisterRoutes(r chi.Router) {
	// Add middleware for WebAuthn routes
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	
	// CORS middleware for WebAuthn endpoints
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add CORS headers for WebAuthn
			w.Header().Set("Access-Control-Allow-Origin", "*") // Configure appropriately for production
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	})

	// Register sub-handlers
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

