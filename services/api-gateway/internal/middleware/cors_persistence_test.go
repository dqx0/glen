package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCORSRepository is a mock implementation of CORSRepository for testing
type MockCORSRepository struct {
	mock.Mock
}

func (m *MockCORSRepository) AddOrigin(ctx context.Context, origin, clientID string) error {
	args := m.Called(ctx, origin, clientID)
	return args.Error(0)
}

func (m *MockCORSRepository) RemoveOrigin(ctx context.Context, origin string) error {
	args := m.Called(ctx, origin)
	return args.Error(0)
}

func (m *MockCORSRepository) GetAllOrigins(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockCORSRepository) RemoveOriginsByClientID(ctx context.Context, clientID string) error {
	args := m.Called(ctx, clientID)
	return args.Error(0)
}

func (m *MockCORSRepository) GetOriginsByClientID(ctx context.Context, clientID string) ([]string, error) {
	args := m.Called(ctx, clientID)
	return args.Get(0).([]string), args.Error(1)
}

func TestCORSMiddleware_LoadPersistedOrigins(t *testing.T) {
	tests := []struct {
		name            string
		persistedOrigins []string
		dbError         error
		expectError     bool
		description     string
	}{
		{
			name:            "Load multiple origins successfully",
			persistedOrigins: []string{"https://example.com", "https://app.com", "http://localhost:3000"},
			dbError:         nil,
			expectError:     false,
			description:     "Should load all persisted origins into memory cache",
		},
		{
			name:            "Load empty origins list",
			persistedOrigins: []string{},
			dbError:         nil,
			expectError:     false,
			description:     "Should handle empty origins list gracefully",
		},
		{
			name:            "Database error",
			persistedOrigins: nil,
			dbError:         errors.New("database connection failed"),
			expectError:     true,
			description:     "Should return error when database fails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(MockCORSRepository)
			
			if tt.dbError != nil {
				mockRepo.On("GetAllOrigins", mock.Anything).Return([]string{}, tt.dbError)
			} else {
				mockRepo.On("GetAllOrigins", mock.Anything).Return(tt.persistedOrigins, nil)
			}

			// Create CORS middleware with persistence
			cors := &CORSMiddleware{
				allowedOrigins:    []string{},
				allowedMethods:    []string{"GET", "POST"},
				allowedHeaders:    []string{"Content-Type"},
				allowCredentials:  true,
				maxAge:           "86400",
				developmentMode:  true,
				repository:       mockRepo,
			}

			// Load persisted origins
			ctx := context.Background()
			err := cors.LoadPersistedOrigins(ctx)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)

				// Verify origins are loaded into memory cache
				for _, origin := range tt.persistedOrigins {
					_, exists := cors.dynamicOrigins.Load(origin)
					assert.True(t, exists, "Origin should be loaded into memory: %s", origin)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestCORSMiddleware_AddDynamicOriginsWithPersistence(t *testing.T) {
	tests := []struct {
		name        string
		origins     []string
		clientID    string
		dbError     error
		expectError bool
		description string
	}{
		{
			name:        "Add origins with successful persistence",
			origins:     []string{"https://example.com", "https://app.com"},
			clientID:    "client_123",
			dbError:     nil,
			expectError: false,
			description: "Should add origins to both memory and database",
		},
		{
			name:        "Add origins with database error",
			origins:     []string{"https://example.com"},
			clientID:    "client_456",
			dbError:     errors.New("database write failed"),
			expectError: false, // Memory operation should still succeed
			description: "Should add to memory even if database fails",
		},
		{
			name:        "Add empty origins list",
			origins:     []string{},
			clientID:    "client_789",
			dbError:     nil,
			expectError: false,
			description: "Should handle empty origins list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(MockCORSRepository)
			
			for _, origin := range tt.origins {
				if tt.dbError != nil {
					mockRepo.On("AddOrigin", mock.Anything, origin, tt.clientID).Return(tt.dbError)
				} else {
					mockRepo.On("AddOrigin", mock.Anything, origin, tt.clientID).Return(nil)
				}
			}

			// Create CORS middleware with persistence
			cors := &CORSMiddleware{
				allowedOrigins:    []string{},
				allowedMethods:    []string{"GET", "POST"},
				allowedHeaders:    []string{"Content-Type"},
				allowCredentials:  true,
				maxAge:           "86400",
				developmentMode:  true,
				repository:       mockRepo,
			}

			// Add origins with persistence
			ctx := context.Background()
			cors.AddDynamicOriginsWithPersistence(ctx, tt.origins, tt.clientID)

			// Verify origins are added to memory cache
			for _, origin := range tt.origins {
				if cors.isValidOrigin(origin) {
					_, exists := cors.dynamicOrigins.Load(origin)
					assert.True(t, exists, "Valid origin should be in memory: %s", origin)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestCORSMiddleware_RemoveDynamicOriginsWithPersistence(t *testing.T) {
	tests := []struct {
		name        string
		origins     []string
		dbError     error
		expectError bool
		description string
	}{
		{
			name:        "Remove origins with successful persistence",
			origins:     []string{"https://example.com", "https://app.com"},
			dbError:     nil,
			expectError: false,
			description: "Should remove origins from both memory and database",
		},
		{
			name:        "Remove origins with database error",
			origins:     []string{"https://example.com"},
			dbError:     errors.New("database delete failed"),
			expectError: false, // Memory operation should still succeed
			description: "Should remove from memory even if database fails",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(MockCORSRepository)
			
			for _, origin := range tt.origins {
				if tt.dbError != nil {
					mockRepo.On("RemoveOrigin", mock.Anything, origin).Return(tt.dbError)
				} else {
					mockRepo.On("RemoveOrigin", mock.Anything, origin).Return(nil)
				}
			}

			// Create CORS middleware with persistence and pre-populate origins
			cors := &CORSMiddleware{
				allowedOrigins:    []string{},
				allowedMethods:    []string{"GET", "POST"},
				allowedHeaders:    []string{"Content-Type"},
				allowCredentials:  true,
				maxAge:           "86400",
				developmentMode:  true,
				repository:       mockRepo,
			}

			// Pre-populate origins in memory
			for _, origin := range tt.origins {
				cors.dynamicOrigins.Store(origin, true)
			}

			// Remove origins with persistence
			ctx := context.Background()
			cors.RemoveDynamicOriginsWithPersistence(ctx, tt.origins)

			// Verify origins are removed from memory cache
			for _, origin := range tt.origins {
				_, exists := cors.dynamicOrigins.Load(origin)
				assert.False(t, exists, "Origin should be removed from memory: %s", origin)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestCORSMiddleware_PersistenceIntegrationFlow(t *testing.T) {
	// Test the complete flow: load, add, verify, remove
	mockRepo := new(MockCORSRepository)

	// Setup expectations
	initialOrigins := []string{"https://existing.com"}
	mockRepo.On("GetAllOrigins", mock.Anything).Return(initialOrigins, nil)
	mockRepo.On("AddOrigin", mock.Anything, "https://new.com", "client_123").Return(nil)
	mockRepo.On("RemoveOrigin", mock.Anything, "https://existing.com").Return(nil)

	// Create CORS middleware
	cors := &CORSMiddleware{
		allowedOrigins:    []string{},
		allowedMethods:    []string{"GET", "POST", "OPTIONS"},
		allowedHeaders:    []string{"Content-Type", "Authorization"},
		allowCredentials:  true,
		maxAge:           "86400",
		developmentMode:  true,
		repository:       mockRepo,
	}

	ctx := context.Background()

	// Step 1: Load persisted origins
	err := cors.LoadPersistedOrigins(ctx)
	require.NoError(t, err)

	// Verify initial origin is loaded
	_, exists := cors.dynamicOrigins.Load("https://existing.com")
	assert.True(t, exists, "Initial origin should be loaded")

	// Step 2: Add new origin
	cors.AddDynamicOriginsWithPersistence(ctx, []string{"https://new.com"}, "client_123")

	// Verify new origin is added
	_, exists = cors.dynamicOrigins.Load("https://new.com")
	assert.True(t, exists, "New origin should be added")

	// Step 3: Test CORS checking with both origins
	testCases := []struct {
		origin   string
		expected bool
	}{
		{"https://existing.com", true},
		{"https://new.com", true},
		{"https://unauthorized.com", false},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", tc.origin)
		recorder := httptest.NewRecorder()

		handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler(recorder, req)

		allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
		if tc.expected {
			assert.Equal(t, tc.origin, allowOriginHeader, "Origin should be allowed: %s", tc.origin)
		} else {
			assert.NotEqual(t, tc.origin, allowOriginHeader, "Origin should not be allowed: %s", tc.origin)
		}
	}

	// Step 4: Remove origin
	cors.RemoveDynamicOriginsWithPersistence(ctx, []string{"https://existing.com"})

	// Verify origin is removed
	_, exists = cors.dynamicOrigins.Load("https://existing.com")
	assert.False(t, exists, "Removed origin should not exist in memory")

	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_PersistenceFailureResilience(t *testing.T) {
	// Test that CORS functionality continues even when persistence fails
	mockRepo := new(MockCORSRepository)
	mockRepo.On("GetAllOrigins", mock.Anything).Return([]string{}, errors.New("database unavailable"))

	cors := &CORSMiddleware{
		allowedOrigins:    []string{"https://static.com"},
		allowedMethods:    []string{"GET", "POST"},
		allowedHeaders:    []string{"Content-Type"},
		allowCredentials:  true,
		maxAge:           "86400",
		developmentMode:  true,
		repository:       mockRepo,
	}

	ctx := context.Background()

	// Loading should fail but not crash
	err := cors.LoadPersistedOrigins(ctx)
	assert.Error(t, err, "Should return error when database fails")

	// But static CORS should still work
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://static.com")
	recorder := httptest.NewRecorder()

	handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler(recorder, req)

	allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
	assert.Equal(t, "https://static.com", allowOriginHeader, "Static CORS should work despite database failure")

	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_OriginValidationWithPersistence(t *testing.T) {
	mockRepo := new(MockCORSRepository)

	cors := &CORSMiddleware{
		allowedOrigins:    []string{},
		allowedMethods:    []string{"GET", "POST"},
		allowedHeaders:    []string{"Content-Type"},
		allowCredentials:  true,
		maxAge:           "86400",
		developmentMode:  false, // Production mode
		repository:       mockRepo,
	}

	ctx := context.Background()

	// Test invalid origins are not persisted
	invalidOrigins := []string{
		"",
		"not-a-url",
		"http://example.com", // HTTP in production
	}

	for _, origin := range invalidOrigins {
		// Should not call repository for invalid origins
		cors.AddDynamicOriginsWithPersistence(ctx, []string{origin}, "client_123")
		
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.False(t, exists, "Invalid origin should not be added: %s", origin)
	}

	// Valid origins should be persisted (in production, HTTPS required)
	validOrigins := []string{
		"https://example.com",
		"https://localhost:3000", // localhost exception
	}

	for _, origin := range validOrigins {
		mockRepo.On("AddOrigin", mock.Anything, origin, "client_456").Return(nil)
		
		cors.AddDynamicOriginsWithPersistence(ctx, []string{origin}, "client_456")
		
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.True(t, exists, "Valid origin should be added: %s", origin)
	}

	mockRepo.AssertExpectations(t)
}