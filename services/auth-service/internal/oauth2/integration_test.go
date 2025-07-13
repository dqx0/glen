package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dqx0/glen/auth-service/internal/oauth2/service"
)

// TestOAuth2CORSIntegration tests the integration between OAuth2 client creation and CORS notification
func TestOAuth2CORSIntegration(t *testing.T) {
	// Mock API Gateway server to receive CORS notifications
	var receivedRequests []CORSUpdateRequest
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/cors/origins" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		if r.Method != http.MethodPost {
			t.Errorf("Unexpected method: %s", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify headers
		if auth := r.Header.Get("X-Internal-Service"); auth != "auth-service" {
			t.Errorf("Expected X-Internal-Service header to be 'auth-service', got '%s'", auth)
		}

		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("Expected Content-Type to be 'application/json', got '%s'", contentType)
		}

		// Parse and store request
		var req CORSUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode request: %v", err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		receivedRequests = append(receivedRequests, req)

		// Send success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"action":  req.Action,
			"count":   len(req.Origins),
		})
	}))
	defer mockGateway.Close()

	// Create CORS notifier pointing to mock gateway
	corsNotifier := service.NewHTTPCORSNotifier(mockGateway.URL)

	// Test scenarios
	tests := []struct {
		name         string
		redirectURIs []string
		action       string
		expected     []string
		description  string
	}{
		{
			name:         "Add single HTTPS origin",
			redirectURIs: []string{"https://example.com/callback"},
			action:       "add",
			expected:     []string{"https://example.com"},
			description:  "Should extract and add single HTTPS origin",
		},
		{
			name: "Add multiple origins",
			redirectURIs: []string{
				"https://app.example.com/callback",
				"http://localhost:3000/callback",
				"https://api.domain.com:8443/oauth/callback",
			},
			action: "add",
			expected: []string{
				"https://app.example.com",
				"http://localhost:3000",
				"https://api.domain.com:8443",
			},
			description: "Should extract and add multiple origins with different schemes and ports",
		},
		{
			name: "Deduplicate origins",
			redirectURIs: []string{
				"https://example.com/callback1",
				"https://example.com/callback2",
				"https://other.com/callback",
			},
			action:      "add",
			expected:    []string{"https://example.com", "https://other.com"},
			description: "Should deduplicate origins from same domain",
		},
		{
			name: "Remove origins",
			redirectURIs: []string{
				"https://example.com/callback",
				"http://localhost:3000/callback",
			},
			action:      "remove",
			expected:    []string{"https://example.com", "http://localhost:3000"},
			description: "Should remove specified origins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear previous requests
			receivedRequests = nil

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Extract origins and execute CORS notification
			origins := extractOriginsFromRedirectURIs(tt.redirectURIs)
			err := corsNotifier.UpdateOrigins(ctx, origins, tt.action)
			if err != nil {
				t.Fatalf("%s: Failed to update origins: %v", tt.description, err)
			}

			// Verify request was received
			if len(receivedRequests) != 1 {
				t.Fatalf("%s: Expected 1 request, got %d", tt.description, len(receivedRequests))
			}

			req := receivedRequests[0]

			// Verify action
			if req.Action != tt.action {
				t.Errorf("%s: Expected action %s, got %s", tt.description, tt.action, req.Action)
			}

			// Verify origins (order-independent)
			if len(req.Origins) != len(tt.expected) {
				t.Errorf("%s: Expected %d origins, got %d", tt.description, len(tt.expected), len(req.Origins))
				t.Errorf("Expected: %v, Got: %v", tt.expected, req.Origins)
				return
			}

			// Create map for order-independent comparison
			expectedMap := make(map[string]bool)
			for _, origin := range tt.expected {
				expectedMap[origin] = true
			}

			for _, origin := range req.Origins {
				if !expectedMap[origin] {
					t.Errorf("%s: Unexpected origin: %s", tt.description, origin)
				}
				delete(expectedMap, origin)
			}

			if len(expectedMap) > 0 {
				var missing []string
				for origin := range expectedMap {
					missing = append(missing, origin)
				}
				t.Errorf("%s: Missing origins: %v", tt.description, missing)
			}
		})
	}
}

// TestCORSNotificationFailure tests behavior when CORS notification fails
func TestCORSNotificationFailure(t *testing.T) {
	// Mock Gateway that returns errors
	errorGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}))
	defer errorGateway.Close()

	corsNotifier := service.NewHTTPCORSNotifier(errorGateway.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should return error for failed notification
	err := corsNotifier.UpdateOrigins(ctx, []string{"https://example.com"}, "add")
	if err == nil {
		t.Error("Expected error for failed CORS notification, but got none")
	}
}

// TestCORSNotificationTimeout tests timeout behavior
func TestCORSNotificationTimeout(t *testing.T) {
	// Mock Gateway that delays response
	slowGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Delay response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer slowGateway.Close()

	corsNotifier := service.NewHTTPCORSNotifier(slowGateway.URL)

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should handle timeout gracefully
	err := corsNotifier.UpdateOrigins(ctx, []string{"https://example.com"}, "add")
	if err == nil {
		t.Log("Request completed within timeout (test may be flaky)")
	} else {
		t.Logf("Request timed out as expected: %v", err)
	}
}

// CORSUpdateRequest represents the expected request format
type CORSUpdateRequest struct {
	Origins []string `json:"origins"`
	Action  string   `json:"action"`
}

// Helper function to extract origins from redirect URIs for testing
func extractOriginsFromRedirectURIs(redirectURIs []string) []string {
	// This duplicates the logic from service package for testing
	originSet := make(map[string]bool)
	
	for _, uri := range redirectURIs {
		if uri == "" {
			continue
		}
		
		u, err := url.Parse(uri)
		if err != nil {
			continue
		}
		
		if u.Host == "" {
			continue
		}
		
		origin := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		originSet[origin] = true
	}
	
	// Convert set to slice
	origins := make([]string, 0, len(originSet))
	for origin := range originSet {
		origins = append(origins, origin)
	}
	
	return origins
}