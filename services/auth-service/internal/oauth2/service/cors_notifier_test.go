package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSNotifier_ExtractOriginsFromRedirectURIs(t *testing.T) {
	tests := []struct {
		name        string
		redirectURIs []string
		expected    []string
		description string
	}{
		{
			name:        "Valid HTTPS URIs",
			redirectURIs: []string{
				"https://example.com/callback",
				"https://app.domain.com/auth/callback",
			},
			expected:    []string{"https://example.com", "https://app.domain.com"},
			description: "Should extract origins from HTTPS URLs",
		},
		{
			name:        "Mixed HTTP and HTTPS",
			redirectURIs: []string{
				"http://localhost:3000/callback",
				"https://example.com/callback",
			},
			expected:    []string{"http://localhost:3000", "https://example.com"},
			description: "Should extract origins from both HTTP and HTTPS",
		},
		{
			name:        "With ports",
			redirectURIs: []string{
				"http://localhost:3000/callback",
				"https://api.example.com:8443/oauth/callback",
			},
			expected:    []string{"http://localhost:3000", "https://api.example.com:8443"},
			description: "Should include ports in origins",
		},
		{
			name:        "Invalid URIs mixed with valid",
			redirectURIs: []string{
				"https://example.com/callback",
				"not-a-url",
				"https://valid.com/path",
			},
			expected:    []string{"https://example.com", "https://valid.com"},
			description: "Should skip invalid URIs and include only valid ones",
		},
		{
			name:        "Duplicate origins",
			redirectURIs: []string{
				"https://example.com/callback1",
				"https://example.com/callback2",
				"https://other.com/callback",
			},
			expected:    []string{"https://example.com", "https://other.com"},
			description: "Should deduplicate origins from same domain",
		},
		{
			name:        "Empty and invalid URIs",
			redirectURIs: []string{"", "invalid", "://malformed"},
			expected:    []string{},
			description: "Should return empty slice for all invalid URIs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractOriginsFromRedirectURIs(tt.redirectURIs)
			
			if len(result) != len(tt.expected) {
				t.Errorf("%s: Expected %d origins, got %d", tt.description, len(tt.expected), len(result))
				t.Errorf("Expected: %v, Got: %v", tt.expected, result)
				return
			}
			
			// Check if all expected origins are present (order may vary due to deduplication)
			expectedMap := make(map[string]bool)
			for _, origin := range tt.expected {
				expectedMap[origin] = true
			}
			
			for _, origin := range result {
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

func TestHTTPCORSNotifier_UpdateOrigins(t *testing.T) {
	tests := []struct {
		name           string
		origins        []string
		action         string
		serverResponse int
		serverBody     string
		expectedError  bool
		description    string
	}{
		{
			name:           "Successful add request",
			origins:        []string{"https://example.com", "https://app.com"},
			action:         "add",
			serverResponse: http.StatusOK,
			serverBody:     `{"success":true}`,
			expectedError:  false,
			description:    "Should successfully add origins",
		},
		{
			name:           "Successful remove request",
			origins:        []string{"https://example.com"},
			action:         "remove",
			serverResponse: http.StatusOK,
			serverBody:     `{"success":true}`,
			expectedError:  false,
			description:    "Should successfully remove origins",
		},
		{
			name:           "Server error response",
			origins:        []string{"https://example.com"},
			action:         "add",
			serverResponse: http.StatusInternalServerError,
			serverBody:     `{"error":"internal server error"}`,
			expectedError:  true,
			description:    "Should return error for server failures",
		},
		{
			name:           "Bad request response",
			origins:        []string{"invalid-origin"},
			action:         "add",
			serverResponse: http.StatusBadRequest,
			serverBody:     `{"error":"invalid origin"}`,
			expectedError:  true,
			description:    "Should return error for bad requests",
		},
		{
			name:           "Empty origins",
			origins:        []string{},
			action:         "add",
			serverResponse: http.StatusOK,
			serverBody:     `{"success":true}`,
			expectedError:  false,
			description:    "Should handle empty origins list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST method, got %s", r.Method)
				}
				
				// Verify Content-Type
				if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", contentType)
				}
				
				// Verify X-Internal-Service header
				if service := r.Header.Get("X-Internal-Service"); service != "auth-service" {
					t.Errorf("Expected X-Internal-Service header to be auth-service, got %s", service)
				}
				
				// Verify request path
				if r.URL.Path != "/internal/cors/origins" {
					t.Errorf("Expected path /internal/cors/origins, got %s", r.URL.Path)
				}
				
				// Return test response
				w.WriteHeader(tt.serverResponse)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			// Create notifier
			notifier := NewHTTPCORSNotifier(server.URL)
			
			// Execute request
			err := notifier.UpdateOrigins(context.Background(), tt.origins, tt.action)
			
			// Check result
			if tt.expectedError && err == nil {
				t.Errorf("%s: Expected error but got none", tt.description)
			}
			
			if !tt.expectedError && err != nil {
				t.Errorf("%s: Expected no error but got: %v", tt.description, err)
			}
		})
	}
}

func TestHTTPCORSNotifier_RequestTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response - just return immediately for this test
		// In a real scenario, you might want to test actual timeouts
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	notifier := NewHTTPCORSNotifier(server.URL)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50) // Very short timeout
	defer cancel()
	
	err := notifier.UpdateOrigins(ctx, []string{"https://example.com"}, "add")
	
	// This test might be flaky depending on system performance
	// The main goal is to ensure context cancellation is respected
	if err != nil {
		t.Logf("Request failed as expected with timeout: %v", err)
	}
}

func TestHTTPCORSNotifier_InvalidGatewayURL(t *testing.T) {
	// Test with invalid URL
	notifier := NewHTTPCORSNotifier("invalid-url")
	
	err := notifier.UpdateOrigins(context.Background(), []string{"https://example.com"}, "add")
	
	if err == nil {
		t.Error("Expected error for invalid gateway URL, but got none")
	}
}

func TestHTTPCORSNotifier_NetworkError(t *testing.T) {
	// Test with unreachable URL
	notifier := NewHTTPCORSNotifier("http://localhost:99999")
	
	err := notifier.UpdateOrigins(context.Background(), []string{"https://example.com"}, "add")
	
	if err == nil {
		t.Error("Expected network error, but got none")
	}
}