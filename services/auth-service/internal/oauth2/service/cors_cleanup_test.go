package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/auth-service/internal/oauth2/models"
)

// MockCORSNotifierForCleanup is a mock for testing CORS cleanup
type MockCORSNotifierForCleanup struct {
	mock.Mock
	removedOrigins []string
	addedOrigins   []string
}

func (m *MockCORSNotifierForCleanup) UpdateOrigins(ctx context.Context, origins []string, action string) error {
	args := m.Called(ctx, origins, action)
	
	if action == "add" {
		m.addedOrigins = append(m.addedOrigins, origins...)
	} else if action == "remove" {
		m.removedOrigins = append(m.removedOrigins, origins...)
	}
	
	return args.Error(0)
}

func (m *MockCORSNotifierForCleanup) GetRemovedOrigins() []string {
	return m.removedOrigins
}

func (m *MockCORSNotifierForCleanup) GetAddedOrigins() []string {
	return m.addedOrigins
}

func (m *MockCORSNotifierForCleanup) Reset() {
	m.removedOrigins = nil
	m.addedOrigins = nil
}

func TestOAuth2Service_DeleteClientWithCORSCleanup(t *testing.T) {
	tests := []struct {
		name           string
		setupClient    *models.OAuth2Client
		clientID       string
		userID         string
		corsError      error
		expectError    bool
		expectedOrigins []string
		description    string
	}{
		{
			name: "Delete client with single origin",
			setupClient: &models.OAuth2Client{
				ID:           "id_123",
				ClientID:     "client_123",
				UserID:       "user_123",
				Name:         "Test App",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			clientID:        "client_123",
			userID:          "user_123",
			corsError:       nil,
			expectError:     false,
			expectedOrigins: []string{"https://example.com"},
			description:     "Should delete client and clean up single CORS origin",
		},
		{
			name: "Delete client with multiple origins",
			setupClient: &models.OAuth2Client{
				ID:       "id_456",
				ClientID: "client_456",
				UserID:   "user_123",
				Name:     "Multi App",
				RedirectURIs: []string{
					"https://app.example.com/callback",
					"http://localhost:3000/callback",
					"https://api.domain.com:8443/oauth/callback",
				},
			},
			clientID:    "client_456",
			userID:      "user_123",
			corsError:   nil,
			expectError: false,
			expectedOrigins: []string{
				"https://app.example.com",
				"http://localhost:3000",
				"https://api.domain.com:8443",
			},
			description: "Should delete client and clean up multiple CORS origins",
		},
		{
			name: "Delete client with duplicate origins",
			setupClient: &models.OAuth2Client{
				ID:       "id_789",
				ClientID: "client_789",
				UserID:   "user_123",
				Name:     "Duplicate App",
				RedirectURIs: []string{
					"https://example.com/callback1",
					"https://example.com/callback2",
					"https://other.com/callback",
				},
			},
			clientID:    "client_789",
			userID:      "user_123",
			corsError:   nil,
			expectError: false,
			expectedOrigins: []string{
				"https://example.com",
				"https://other.com",
			},
			description: "Should deduplicate origins before CORS cleanup",
		},
		{
			name: "Delete client with CORS notification failure",
			setupClient: &models.OAuth2Client{
				ID:           "id_error",
				ClientID:     "client_error",
				UserID:       "user_123",
				Name:         "Error App",
				RedirectURIs: []string{"https://error.com/callback"},
			},
			clientID:        "client_error",
			userID:          "user_123",
			corsError:       errors.New("CORS notification failed"),
			expectError:     false, // Should not fail client deletion
			expectedOrigins: []string{"https://error.com"},
			description:     "Should delete client even if CORS cleanup fails",
		},
		{
			name: "Delete non-existent client",
			setupClient: &models.OAuth2Client{
				ID:       "id_real",
				ClientID: "client_real",
				UserID:   "user_123",
				Name:     "Real App",
				RedirectURIs: []string{"https://real.com/callback"},
			},
			clientID:        "client_nonexistent",
			userID:          "user_123",
			corsError:       nil,
			expectError:     true,
			expectedOrigins: nil,
			description:     "Should return error for non-existent client",
		},
		{
			name: "Delete client with wrong user",
			setupClient: &models.OAuth2Client{
				ID:       "id_wrong",
				ClientID: "client_wrong",
				UserID:   "user_123",
				Name:     "Wrong User App",
				RedirectURIs: []string{"https://wrong.com/callback"},
			},
			clientID:        "client_wrong",
			userID:          "user_456", // Different user
			corsError:       nil,
			expectError:     true,
			expectedOrigins: nil,
			description:     "Should return error when user doesn't own client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock repository
			mockRepo := newMockOAuth2Repository()
			
			// Setup client in repository if provided
			if tt.setupClient != nil {
				mockRepo.clients[tt.setupClient.ClientID] = tt.setupClient
			}

			// Create mock CORS notifier
			mockCORS := &MockCORSNotifierForCleanup{}
			mockCORS.Reset()

			if tt.expectedOrigins != nil {
				if tt.corsError != nil {
					mockCORS.On("UpdateOrigins", mock.Anything, 
						mock.MatchedBy(func(origins []string) bool {
							return containsAllOrigins(origins, tt.expectedOrigins)
						}), "remove").Return(tt.corsError)
				} else {
					mockCORS.On("UpdateOrigins", mock.Anything,
						mock.MatchedBy(func(origins []string) bool {
							return containsAllOrigins(origins, tt.expectedOrigins)
						}), "remove").Return(nil)
				}
			}

			// Create service with CORS notifier
			service := NewOAuth2ServiceWithCORS(mockRepo, mockCORS)

			// Execute deletion
			ctx := context.Background()
			err := service.DeleteClient(ctx, tt.clientID, tt.userID)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)

				// Verify client was deleted from repository
				_, exists := mockRepo.clients[tt.clientID]
				assert.False(t, exists, "Client should be deleted from repository")

				// Verify CORS cleanup was called if expected
				if tt.expectedOrigins != nil {
					removedOrigins := mockCORS.GetRemovedOrigins()
					assert.ElementsMatch(t, tt.expectedOrigins, removedOrigins,
						"Expected origins should be removed from CORS")
				}
			}

			mockCORS.AssertExpectations(t)
		})
	}
}

func TestOAuth2Service_CreateClientThenDeleteWithCORSFlow(t *testing.T) {
	// Test the complete flow: create client (adds CORS) -> delete client (removes CORS)
	mockRepo := newMockOAuth2Repository()
	mockCORS := &MockCORSNotifierForCleanup{}

	service := NewOAuth2ServiceWithCORS(mockRepo, mockCORS)
	ctx := context.Background()

	// Test data
	userID := "user_flow"
	clientName := "Flow Test App"
	redirectURIs := []string{
		"https://flowapp.com/callback",
		"http://localhost:3000/callback",
	}
	expectedOrigins := []string{
		"https://flowapp.com",
		"http://localhost:3000",
	}

	// Setup CORS expectations
	mockCORS.On("UpdateOrigins", mock.Anything,
		mock.MatchedBy(func(origins []string) bool {
			return containsAllOrigins(origins, expectedOrigins)
		}), "add").Return(nil)

	mockCORS.On("UpdateOrigins", mock.Anything,
		mock.MatchedBy(func(origins []string) bool {
			return containsAllOrigins(origins, expectedOrigins)
		}), "remove").Return(nil)

	// Step 1: Create client
	client, err := service.CreateClient(ctx, userID, clientName, "Test description", redirectURIs, []string{"read"}, false)
	require.NoError(t, err, "Client creation should succeed")
	require.NotNil(t, client, "Created client should not be nil")

	// Verify CORS origins were added
	addedOrigins := mockCORS.GetAddedOrigins()
	assert.ElementsMatch(t, expectedOrigins, addedOrigins, "Origins should be added to CORS on client creation")

	// Step 2: Delete client
	mockCORS.Reset() // Clear previous calls
	err = service.DeleteClient(ctx, client.ClientID, userID)
	require.NoError(t, err, "Client deletion should succeed")

	// Verify CORS origins were removed
	removedOrigins := mockCORS.GetRemovedOrigins()
	assert.ElementsMatch(t, expectedOrigins, removedOrigins, "Origins should be removed from CORS on client deletion")

	// Verify client no longer exists
	_, exists := mockRepo.clients[client.ClientID]
	assert.False(t, exists, "Client should be deleted from repository")

	mockCORS.AssertExpectations(t)
}

func TestOAuth2Service_ConcurrentClientDeletionWithCORS(t *testing.T) {
	// Test concurrent client deletions don't interfere with CORS cleanup
	mockRepo := newMockOAuth2Repository()
	mockCORS := &MockCORSNotifierForCleanup{}

	service := NewOAuth2ServiceWithCORS(mockRepo, mockCORS)
	ctx := context.Background()

	// Setup multiple clients
	clients := []*models.OAuth2Client{
		{
			ID:           "id_1",
			ClientID:     "client_1",
			UserID:       "user_1",
			Name:         "App 1",
			RedirectURIs: []string{"https://app1.com/callback"},
		},
		{
			ID:           "id_2",
			ClientID:     "client_2", 
			UserID:       "user_2",
			Name:         "App 2",
			RedirectURIs: []string{"https://app2.com/callback"},
		},
		{
			ID:           "id_3",
			ClientID:     "client_3",
			UserID:       "user_3",
			Name:         "App 3",
			RedirectURIs: []string{"https://app3.com/callback"},
		},
	}

	for _, client := range clients {
		mockRepo.clients[client.ClientID] = client
	}

	// Setup CORS expectations for each deletion
	for _, client := range clients {
		expectedOrigins := extractOriginsFromRedirectURIs(client.RedirectURIs)
		mockCORS.On("UpdateOrigins", mock.Anything,
			mock.MatchedBy(func(origins []string) bool {
				return containsAllOrigins(origins, expectedOrigins)
			}), "remove").Return(nil)
	}

	// Perform concurrent deletions
	done := make(chan error, len(clients))
	for _, client := range clients {
		go func(c *models.OAuth2Client) {
			done <- service.DeleteClient(ctx, c.ClientID, c.UserID)
		}(client)
	}

	// Wait for all deletions to complete
	for i := 0; i < len(clients); i++ {
		err := <-done
		assert.NoError(t, err, "Concurrent deletion should succeed")
	}

	// Verify all clients are deleted
	for _, client := range clients {
		_, exists := mockRepo.clients[client.ClientID]
		assert.False(t, exists, "Client should be deleted: %s", client.ClientID)
	}

	// Verify CORS cleanup was called for all clients
	removedOrigins := mockCORS.GetRemovedOrigins()
	expectedTotalOrigins := []string{"https://app1.com", "https://app2.com", "https://app3.com"}
	assert.ElementsMatch(t, expectedTotalOrigins, removedOrigins, 
		"All origins should be removed from CORS")

	mockCORS.AssertExpectations(t)
}

// Helper function to check if slice contains all expected origins
func containsAllOrigins(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}

	actualSet := make(map[string]bool)
	for _, origin := range actual {
		actualSet[origin] = true
	}

	for _, expectedOrigin := range expected {
		if !actualSet[expectedOrigin] {
			return false
		}
	}

	return true
}

func TestCORSCleanupWithAPIGatewayIntegration(t *testing.T) {
	// Integration test with mock API Gateway
	var receivedRequests []CORSUpdateRequest
	
	mockGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/cors/origins" {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		var req CORSUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		receivedRequests = append(receivedRequests, req)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"action":  req.Action,
			"count":   len(req.Origins),
		})
	}))
	defer mockGateway.Close()

	// Create service with real HTTP CORS notifier
	mockRepo := newMockOAuth2Repository()
	corsNotifier := NewHTTPCORSNotifier(mockGateway.URL)
	service := NewOAuth2ServiceWithCORS(mockRepo, corsNotifier)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create and then delete a client
	redirectURIs := []string{
		"https://integration.com/callback",
		"http://localhost:3000/callback",
	}
	expectedOrigins := []string{
		"https://integration.com",
		"http://localhost:3000",
	}

	// Create client
	client, err := service.CreateClient(ctx, "user_integration", "Integration App", 
		"Integration test app", redirectURIs, []string{"read"}, false)
	require.NoError(t, err)

	// Delete client
	err = service.DeleteClient(ctx, client.ClientID, "user_integration")
	require.NoError(t, err)

	// Verify requests were sent to mock gateway
	require.Len(t, receivedRequests, 2, "Should have received 2 requests (add + remove)")

	// Verify add request
	addRequest := receivedRequests[0]
	assert.Equal(t, "add", addRequest.Action)
	assert.ElementsMatch(t, expectedOrigins, addRequest.Origins)

	// Verify remove request
	removeRequest := receivedRequests[1]
	assert.Equal(t, "remove", removeRequest.Action)
	assert.ElementsMatch(t, expectedOrigins, removeRequest.Origins)
}

// CORSUpdateRequest represents the expected request format
type CORSUpdateRequest struct {
	Origins []string `json:"origins"`
	Action  string   `json:"action"`
}