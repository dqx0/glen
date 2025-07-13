package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockCORSMiddleware struct {
	addedOrigins   []string
	removedOrigins []string
}

func (m *mockCORSMiddleware) AddDynamicOrigins(origins []string) {
	m.addedOrigins = append(m.addedOrigins, origins...)
}

func (m *mockCORSMiddleware) RemoveDynamicOrigins(origins []string) {
	m.removedOrigins = append(m.removedOrigins, origins...)
}

func (m *mockCORSMiddleware) GetDynamicOrigins() []string {
	return m.addedOrigins
}

func TestCORSHandler_UpdateOrigins(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedAdded  []string
		expectedRemoved []string
		description    string
	}{
		{
			name: "Add valid origins",
			requestBody: map[string]interface{}{
				"origins": []string{"https://example.com", "https://app.com"},
				"action":  "add",
			},
			expectedStatus: http.StatusOK,
			expectedAdded:  []string{"https://example.com", "https://app.com"},
			description:    "Should add valid origins to CORS middleware",
		},
		{
			name: "Remove origins",
			requestBody: map[string]interface{}{
				"origins": []string{"https://example.com"},
				"action":  "remove",
			},
			expectedStatus:  http.StatusOK,
			expectedRemoved: []string{"https://example.com"},
			description:     "Should remove origins from CORS middleware",
		},
		{
			name: "Invalid action",
			requestBody: map[string]interface{}{
				"origins": []string{"https://example.com"},
				"action":  "invalid",
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject invalid action",
		},
		{
			name: "Missing action",
			requestBody: map[string]interface{}{
				"origins": []string{"https://example.com"},
			},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject missing action",
		},
		{
			name: "Empty origins array",
			requestBody: map[string]interface{}{
				"origins": []string{},
				"action":  "add",
			},
			expectedStatus: http.StatusOK,
			expectedAdded:  []string{},
			description:    "Should handle empty origins array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock CORS middleware
			mockCORS := &mockCORSMiddleware{}
			handler := NewCORSHandler(mockCORS)

			// Create request body
			requestBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Create HTTP request
			req := httptest.NewRequest("POST", "/internal/cors/origins", bytes.NewBuffer(requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Internal-Service", "auth-service")

			// Create response recorder
			recorder := httptest.NewRecorder()

			// Execute request
			handler.UpdateOrigins(recorder, req)

			// Check status code
			if recorder.Code != tt.expectedStatus {
				t.Errorf("%s: Expected status %d, got %d", tt.description, tt.expectedStatus, recorder.Code)
			}

			// Check expected behavior (only for successful requests)
			if tt.expectedStatus == http.StatusOK {
				if tt.expectedAdded != nil {
					if len(mockCORS.addedOrigins) != len(tt.expectedAdded) {
						t.Errorf("%s: Expected %d added origins, got %d", tt.description, len(tt.expectedAdded), len(mockCORS.addedOrigins))
					}
					for i, expected := range tt.expectedAdded {
						if i >= len(mockCORS.addedOrigins) || mockCORS.addedOrigins[i] != expected {
							t.Errorf("%s: Expected added origin %s, got %v", tt.description, expected, mockCORS.addedOrigins)
						}
					}
				}

				if tt.expectedRemoved != nil {
					if len(mockCORS.removedOrigins) != len(tt.expectedRemoved) {
						t.Errorf("%s: Expected %d removed origins, got %d", tt.description, len(tt.expectedRemoved), len(mockCORS.removedOrigins))
					}
					for i, expected := range tt.expectedRemoved {
						if i >= len(mockCORS.removedOrigins) || mockCORS.removedOrigins[i] != expected {
							t.Errorf("%s: Expected removed origin %s, got %v", tt.description, expected, mockCORS.removedOrigins)
						}
					}
				}
			}
		})
	}
}

func TestCORSHandler_InvalidJSON(t *testing.T) {
	mockCORS := &mockCORSMiddleware{}
	handler := NewCORSHandler(mockCORS)

	req := httptest.NewRequest("POST", "/internal/cors/origins", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Service", "auth-service") // Add authentication header

	recorder := httptest.NewRecorder()
	handler.UpdateOrigins(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", recorder.Code)
	}
}

func TestCORSHandler_MethodNotAllowed(t *testing.T) {
	mockCORS := &mockCORSMiddleware{}
	handler := NewCORSHandler(mockCORS)

	req := httptest.NewRequest("GET", "/internal/cors/origins", nil)
	recorder := httptest.NewRecorder()
	handler.UpdateOrigins(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 for GET method, got %d", recorder.Code)
	}
}

func TestCORSHandler_GetOrigins(t *testing.T) {
	mockCORS := &mockCORSMiddleware{}
	mockCORS.addedOrigins = []string{"https://example.com", "https://app.com"}
	handler := NewCORSHandler(mockCORS)

	req := httptest.NewRequest("GET", "/internal/cors/origins", nil)
	req.Header.Set("X-Internal-Service", "auth-service")

	recorder := httptest.NewRecorder()
	handler.GetOrigins(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	var response map[string][]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	origins, exists := response["origins"]
	if !exists {
		t.Error("Response should contain 'origins' field")
	}

	if len(origins) != 2 {
		t.Errorf("Expected 2 origins, got %d", len(origins))
	}

	expectedOrigins := []string{"https://example.com", "https://app.com"}
	for i, expected := range expectedOrigins {
		if i >= len(origins) || origins[i] != expected {
			t.Errorf("Expected origin %s, got %v", expected, origins)
		}
	}
}

func TestCORSHandler_InternalServiceAuthentication(t *testing.T) {
	mockCORS := &mockCORSMiddleware{}
	handler := NewCORSHandler(mockCORS)

	requestBody := map[string]interface{}{
		"origins": []string{"https://example.com"},
		"action":  "add",
	}
	body, _ := json.Marshal(requestBody)

	// Test without internal service header
	req := httptest.NewRequest("POST", "/internal/cors/origins", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.UpdateOrigins(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 without internal service header, got %d", recorder.Code)
	}

	// Test with wrong internal service header
	req = httptest.NewRequest("POST", "/internal/cors/origins", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Service", "external-service")

	recorder = httptest.NewRecorder()
	handler.UpdateOrigins(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with wrong internal service header, got %d", recorder.Code)
	}
}