package handlers

import (
	"encoding/json"
	"net/http"
)

// CORSMiddlewareInterface defines the interface for CORS middleware operations
type CORSMiddlewareInterface interface {
	AddDynamicOrigins(origins []string)
	RemoveDynamicOrigins(origins []string)
	GetDynamicOrigins() []string
}

// CORSHandler handles CORS management endpoints
type CORSHandler struct {
	corsMiddleware CORSMiddlewareInterface
}

// NewCORSHandler creates a new CORSHandler
func NewCORSHandler(corsMiddleware CORSMiddlewareInterface) *CORSHandler {
	return &CORSHandler{
		corsMiddleware: corsMiddleware,
	}
}

// UpdateOriginsRequest represents a request to update CORS origins
type UpdateOriginsRequest struct {
	Origins []string `json:"origins"`
	Action  string   `json:"action"` // "add" or "remove"
}

// UpdateOrigins handles requests to update CORS origins dynamically
// POST /internal/cors/origins
func (h *CORSHandler) UpdateOrigins(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify internal service authentication
	if !h.isInternalService(r) {
		http.Error(w, "Unauthorized: Internal service access required", http.StatusUnauthorized)
		return
	}

	var req UpdateOriginsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate action
	if req.Action != "add" && req.Action != "remove" {
		http.Error(w, "Invalid action. Must be 'add' or 'remove'", http.StatusBadRequest)
		return
	}

	// Execute action
	switch req.Action {
	case "add":
		h.corsMiddleware.AddDynamicOrigins(req.Origins)
	case "remove":
		h.corsMiddleware.RemoveDynamicOrigins(req.Origins)
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"success": true,
		"action":  req.Action,
		"count":   len(req.Origins),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
	}
}

// GetOrigins returns the current list of dynamic CORS origins
// GET /internal/cors/origins
func (h *CORSHandler) GetOrigins(w http.ResponseWriter, r *http.Request) {
	// Only allow GET method
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify internal service authentication
	if !h.isInternalService(r) {
		http.Error(w, "Unauthorized: Internal service access required", http.StatusUnauthorized)
		return
	}

	origins := h.corsMiddleware.GetDynamicOrigins()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string][]string{
		"origins": origins,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// isInternalService checks if the request comes from an authorized internal service
func (h *CORSHandler) isInternalService(r *http.Request) bool {
	// Check for internal service header
	internalService := r.Header.Get("X-Internal-Service")

	// Allow requests from specific internal services
	allowedServices := []string{
		"auth-service",
		"user-service",
		"social-service",
	}

	for _, service := range allowedServices {
		if internalService == service {
			return true
		}
	}

	// In development mode, also check for localhost requests
	if r.Header.Get("X-Forwarded-For") == "" &&
		(r.RemoteAddr == "127.0.0.1" || r.RemoteAddr == "[::1]" ||
			r.Host == "localhost:8080" || r.Host == "127.0.0.1:8080") {
		return true
	}

	return false
}
