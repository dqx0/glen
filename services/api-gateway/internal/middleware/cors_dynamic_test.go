package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware_DynamicOrigins(t *testing.T) {
	tests := []struct {
		name           string
		setupOrigins   []string
		requestOrigin  string
		expectedAllow  bool
		description    string
	}{
		{
			name:          "Add valid origin",
			setupOrigins:  []string{"https://example.com"},
			requestOrigin: "https://example.com",
			expectedAllow: true,
			description:   "Dynamic origin should be allowed",
		},
		{
			name:          "Remove origin",
			setupOrigins:  []string{}, // Will be added then removed
			requestOrigin: "https://removed.com",
			expectedAllow: false,
			description:   "Removed origin should not be allowed",
		},
		{
			name:          "Multiple origins",
			setupOrigins:  []string{"https://app1.com", "https://app2.com"},
			requestOrigin: "https://app2.com",
			expectedAllow: true,
			description:   "Second dynamic origin should be allowed",
		},
		{
			name:          "Invalid origin rejected",
			setupOrigins:  []string{"invalid-url"},
			requestOrigin: "invalid-url",
			expectedAllow: false,
			description:   "Invalid URL should be rejected",
		},
		{
			name:          "HTTP origin in development",
			setupOrigins:  []string{"http://localhost:3000"},
			requestOrigin: "http://localhost:3000",
			expectedAllow: true,
			description:   "HTTP localhost should be allowed in dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware instance for development mode
			cors := &CORSMiddleware{
				allowedOrigins:    []string{},
				allowedMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				allowedHeaders:    []string{"Content-Type", "Authorization"},
				allowCredentials:  true,
				maxAge:           "86400",
				developmentMode:  true,
				allowAnyLocalhost: true,
			}

			// Setup dynamic origins
			if tt.name == "Remove origin" {
				// Add then remove
				cors.AddDynamicOrigins([]string{"https://removed.com"})
				cors.RemoveDynamicOrigins([]string{"https://removed.com"})
			} else {
				cors.AddDynamicOrigins(tt.setupOrigins)
			}

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.requestOrigin)
			
			recorder := httptest.NewRecorder()
			
			// Create test handler
			handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			
			// Execute request
			handler(recorder, req)
			
			// Check CORS header
			allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
			
			if tt.expectedAllow {
				if allowOriginHeader != tt.requestOrigin {
					t.Errorf("%s: Expected Allow-Origin header to be %s, got %s", 
						tt.description, tt.requestOrigin, allowOriginHeader)
				}
			} else {
				if allowOriginHeader == tt.requestOrigin {
					t.Errorf("%s: Expected origin to be rejected, but got Allow-Origin: %s", 
						tt.description, allowOriginHeader)
				}
			}
		})
	}
}

func TestCORSMiddleware_OriginValidation(t *testing.T) {
	tests := []struct {
		name        string
		origin      string
		development bool
		expected    bool
	}{
		{
			name:        "Valid HTTPS origin",
			origin:      "https://example.com",
			development: false,
			expected:    true,
		},
		{
			name:        "HTTP origin in production",
			origin:      "http://example.com",
			development: false,
			expected:    false,
		},
		{
			name:        "HTTP localhost in production",
			origin:      "http://localhost:3000",
			development: false,
			expected:    true,
		},
		{
			name:        "HTTP origin in development",
			origin:      "http://example.com",
			development: true,
			expected:    true,
		},
		{
			name:        "Invalid URL",
			origin:      "not-a-url",
			development: true,
			expected:    false,
		},
		{
			name:        "Empty origin",
			origin:      "",
			development: true,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cors := &CORSMiddleware{
				developmentMode: tt.development,
			}
			
			result := cors.isValidOrigin(tt.origin)
			if result != tt.expected {
				t.Errorf("isValidOrigin(%s) in dev=%v: expected %v, got %v", 
					tt.origin, tt.development, tt.expected, result)
			}
		})
	}
}

func TestCORSMiddleware_ConcurrentAccess(t *testing.T) {
	cors := &CORSMiddleware{
		allowedOrigins:    []string{},
		developmentMode:  true,
		allowAnyLocalhost: true,
	}

	// Test concurrent adds and removes
	origins := []string{
		"https://app1.com",
		"https://app2.com", 
		"https://app3.com",
		"https://app4.com",
		"https://app5.com",
	}

	// Add origins concurrently
	done := make(chan bool, len(origins))
	for _, origin := range origins {
		go func(o string) {
			cors.AddDynamicOrigins([]string{o})
			done <- true
		}(origin)
	}

	// Wait for all adds to complete
	for i := 0; i < len(origins); i++ {
		<-done
	}

	// Test that all origins were added
	for _, origin := range origins {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		recorder := httptest.NewRecorder()
		
		handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		
		handler(recorder, req)
		
		allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
		if allowOriginHeader != origin {
			t.Errorf("Concurrent add failed: expected %s, got %s", origin, allowOriginHeader)
		}
	}

	// Remove origins concurrently
	for _, origin := range origins {
		go func(o string) {
			cors.RemoveDynamicOrigins([]string{o})
			done <- true
		}(origin)
	}

	// Wait for all removes to complete
	for i := 0; i < len(origins); i++ {
		<-done
	}

	// Test that all origins were removed
	for _, origin := range origins {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		recorder := httptest.NewRecorder()
		
		handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		
		handler(recorder, req)
		
		allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
		if allowOriginHeader == origin {
			t.Errorf("Concurrent remove failed: origin %s should have been removed", origin)
		}
	}
}