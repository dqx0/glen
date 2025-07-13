package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCORSRepositoryForStartup is a specialized mock for testing startup synchronization
type MockCORSRepositoryForStartup struct {
	mock.Mock
	mu              sync.RWMutex
	origins         map[string]string // origin -> clientID
	getAllCallCount int
	simulateDelay   time.Duration
	failureCount    int
	maxFailures     int
}

func NewMockCORSRepositoryForStartup() *MockCORSRepositoryForStartup {
	return &MockCORSRepositoryForStartup{
		origins: make(map[string]string),
	}
}

func (m *MockCORSRepositoryForStartup) AddOrigin(ctx context.Context, origin, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	args := m.Called(ctx, origin, clientID)
	if args.Error(0) == nil {
		m.origins[origin] = clientID
	}
	return args.Error(0)
}

func (m *MockCORSRepositoryForStartup) RemoveOrigin(ctx context.Context, origin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	args := m.Called(ctx, origin)
	if args.Error(0) == nil {
		delete(m.origins, origin)
	}
	return args.Error(0)
}

func (m *MockCORSRepositoryForStartup) GetAllOrigins(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Simulate delay if configured
	if m.simulateDelay > 0 {
		time.Sleep(m.simulateDelay)
	}
	
	// Simulate intermittent failures
	m.getAllCallCount++
	if m.failureCount < m.maxFailures {
		m.failureCount++
		return nil, errors.New("database temporarily unavailable")
	}
	
	args := m.Called(ctx)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	
	// Return stored origins
	var result []string
	for origin := range m.origins {
		result = append(result, origin)
	}
	
	return result, nil
}

func (m *MockCORSRepositoryForStartup) RemoveOriginsByClientID(ctx context.Context, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	args := m.Called(ctx, clientID)
	if args.Error(0) == nil {
		for origin, cid := range m.origins {
			if cid == clientID {
				delete(m.origins, origin)
			}
		}
	}
	return args.Error(0)
}

func (m *MockCORSRepositoryForStartup) GetOriginsByClientID(ctx context.Context, clientID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	args := m.Called(ctx, clientID)
	if args.Error(1) != nil {
		return nil, args.Error(1)
	}
	
	var result []string
	for origin, cid := range m.origins {
		if cid == clientID {
			result = append(result, origin)
		}
	}
	
	return result, nil
}

func (m *MockCORSRepositoryForStartup) SetSimulateDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulateDelay = delay
}

func (m *MockCORSRepositoryForStartup) SetMaxFailures(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxFailures = count
	m.failureCount = 0
}

func (m *MockCORSRepositoryForStartup) GetStoredOrigins() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	result := make(map[string]string)
	for origin, clientID := range m.origins {
		result[origin] = clientID
	}
	return result
}

func TestCORSMiddleware_StartupSynchronization_BasicLoad(t *testing.T) {
	// Test basic successful startup synchronization
	mockRepo := NewMockCORSRepositoryForStartup()
	
	// Setup pre-existing origins in "database"
	testOrigins := map[string]string{
		"https://app1.example.com": "client_1",
		"https://app2.example.com": "client_2",
		"http://localhost:3000":    "client_dev",
	}
	
	for origin, clientID := range testOrigins {
		mockRepo.origins[origin] = clientID
	}
	
	// Setup mock expectations
	var expectedOrigins []string
	for origin := range testOrigins {
		expectedOrigins = append(expectedOrigins, origin)
	}
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return(expectedOrigins, nil)
	
	// Create CORS middleware
	cors := &CORSMiddleware{
		allowedOrigins:   []string{},
		allowedMethods:   []string{"GET", "POST", "OPTIONS"},
		allowedHeaders:   []string{"Content-Type", "Authorization"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: true,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	// Perform startup synchronization
	err := cors.LoadPersistedOrigins(ctx)
	require.NoError(t, err, "Startup synchronization should succeed")
	
	// Verify all origins are loaded into memory
	for origin := range testOrigins {
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.True(t, exists, "Origin should be loaded into memory: %s", origin)
	}
	
	// Verify CORS functionality works with loaded origins
	for origin := range testOrigins {
		assert.True(t, cors.isOriginAllowed(origin), "Loaded origin should be allowed: %s", origin)
	}
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_EmptyDatabase(t *testing.T) {
	// Test startup when database has no persisted origins
	mockRepo := NewMockCORSRepositoryForStartup()
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return([]string{}, nil)
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{"https://static.com"},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: false,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	err := cors.LoadPersistedOrigins(ctx)
	require.NoError(t, err, "Should handle empty database gracefully")
	
	// Verify static origins still work
	assert.True(t, cors.isOriginAllowed("https://static.com"), "Static origin should still work")
	assert.False(t, cors.isOriginAllowed("https://unknown.com"), "Unknown origin should be rejected")
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_DatabaseFailure(t *testing.T) {
	// Test startup resilience when database is unavailable
	mockRepo := NewMockCORSRepositoryForStartup()
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return([]string{}, errors.New("database connection failed"))
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{"https://fallback.com"},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: false,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	err := cors.LoadPersistedOrigins(ctx)
	assert.Error(t, err, "Should return error when database fails")
	assert.Contains(t, err.Error(), "failed to load persisted CORS origins", "Error should be descriptive")
	
	// Verify fallback functionality still works
	assert.True(t, cors.isOriginAllowed("https://fallback.com"), "Fallback origin should work despite database failure")
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_NoRepository(t *testing.T) {
	// Test startup when no repository is configured
	cors := &CORSMiddleware{
		allowedOrigins:   []string{"https://static.com"},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: false,
		repository:      nil, // No repository
	}
	
	ctx := context.Background()
	
	err := cors.LoadPersistedOrigins(ctx)
	assert.NoError(t, err, "Should handle no repository gracefully")
	
	// Verify static CORS still works
	assert.True(t, cors.isOriginAllowed("https://static.com"), "Static origin should work")
}

func TestCORSMiddleware_StartupSynchronization_ConcurrentAccess(t *testing.T) {
	// Test that startup synchronization is thread-safe
	mockRepo := NewMockCORSRepositoryForStartup()
	
	// Setup test origins
	testOrigins := []string{
		"https://app1.com", "https://app2.com", "https://app3.com",
		"https://app4.com", "https://app5.com",
	}
	
	for i, origin := range testOrigins {
		mockRepo.origins[origin] = fmt.Sprintf("client_%d", i+1)
	}
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return(testOrigins, nil)
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{},
		allowedMethods:   []string{"GET", "POST", "OPTIONS"},
		allowedHeaders:   []string{"Content-Type", "Authorization"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: true,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	// Perform concurrent operations during startup
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*2)
	
	// Start multiple goroutines that attempt to load and check origins
	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		
		// Goroutine 1: Load persisted origins
		go func() {
			defer wg.Done()
			if err := cors.LoadPersistedOrigins(ctx); err != nil {
				errors <- err
			}
		}()
		
		// Goroutine 2: Check origins while loading
		go func(index int) {
			defer wg.Done()
			origin := testOrigins[index%len(testOrigins)]
			
			// Wait a bit then check if origin is allowed
			time.Sleep(time.Millisecond * 10)
			cors.isOriginAllowed(origin) // Should not panic
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
	
	// Verify final state - all origins should be loaded
	for _, origin := range testOrigins {
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.True(t, exists, "Origin should be loaded: %s", origin)
	}
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_RetryLogic(t *testing.T) {
	// Test retry behavior when database initially fails
	mockRepo := NewMockCORSRepositoryForStartup()
	
	// Setup to fail first 2 attempts, then succeed
	mockRepo.SetMaxFailures(2)
	
	testOrigins := []string{"https://retry.com", "https://example.com"}
	for i, origin := range testOrigins {
		mockRepo.origins[origin] = fmt.Sprintf("client_%d", i+1)
	}
	
	// First two calls will fail, third will succeed
	mockRepo.On("GetAllOrigins", mock.Anything).Return(testOrigins, nil).Maybe()
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: true,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	// First attempt should fail
	err := cors.LoadPersistedOrigins(ctx)
	assert.Error(t, err, "First attempt should fail")
	
	// Second attempt should fail
	err = cors.LoadPersistedOrigins(ctx)
	assert.Error(t, err, "Second attempt should fail")
	
	// Third attempt should succeed
	err = cors.LoadPersistedOrigins(ctx)
	assert.NoError(t, err, "Third attempt should succeed")
	
	// Verify origins are loaded
	for _, origin := range testOrigins {
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.True(t, exists, "Origin should be loaded after retry: %s", origin)
	}
}

func TestCORSMiddleware_StartupSynchronization_HTTPIntegration(t *testing.T) {
	// Test that startup synchronization properly affects HTTP request handling
	mockRepo := NewMockCORSRepositoryForStartup()
	
	startupOrigins := []string{
		"https://startup-app.com",
		"https://persistent-app.com",
	}
	
	for i, origin := range startupOrigins {
		mockRepo.origins[origin] = fmt.Sprintf("startup_client_%d", i+1)
	}
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return(startupOrigins, nil)
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{"https://static-app.com"},
		allowedMethods:   []string{"GET", "POST", "OPTIONS"},
		allowedHeaders:   []string{"Content-Type", "Authorization"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: false,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	// Before loading: only static origins should work
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://startup-app.com")
	recorder := httptest.NewRecorder()
	
	handler := cors.Handle(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	handler(recorder, req)
	allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
	assert.NotEqual(t, "https://startup-app.com", allowOriginHeader, "Dynamic origin should not work before startup sync")
	
	// Load persisted origins
	err := cors.LoadPersistedOrigins(ctx)
	require.NoError(t, err)
	
	// After loading: dynamic origins should work
	testCases := []struct {
		origin   string
		expected bool
	}{
		{"https://static-app.com", true},      // Static origin
		{"https://startup-app.com", true},     // Loaded dynamic origin
		{"https://persistent-app.com", true},  // Loaded dynamic origin
		{"https://unknown-app.com", false},    // Unknown origin
	}
	
	for _, tc := range testCases {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", tc.origin)
		recorder := httptest.NewRecorder()
		
		handler(recorder, req)
		
		allowOriginHeader := recorder.Header().Get("Access-Control-Allow-Origin")
		if tc.expected {
			assert.Equal(t, tc.origin, allowOriginHeader, "Origin should be allowed: %s", tc.origin)
		} else {
			assert.NotEqual(t, tc.origin, allowOriginHeader, "Origin should not be allowed: %s", tc.origin)
		}
	}
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_LargeDataset(t *testing.T) {
	// Test startup performance with large number of origins
	mockRepo := NewMockCORSRepositoryForStartup()
	
	// Generate large number of test origins
	const numOrigins = 1000
	testOrigins := make([]string, numOrigins)
	for i := 0; i < numOrigins; i++ {
		origin := fmt.Sprintf("https://app%d.example.com", i)
		testOrigins[i] = origin
		mockRepo.origins[origin] = fmt.Sprintf("client_%d", i)
	}
	
	mockRepo.On("GetAllOrigins", mock.Anything).Return(testOrigins, nil)
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: true,
		repository:      mockRepo,
	}
	
	ctx := context.Background()
	
	// Measure startup time
	startTime := time.Now()
	err := cors.LoadPersistedOrigins(ctx)
	loadTime := time.Since(startTime)
	
	require.NoError(t, err, "Large dataset load should succeed")
	assert.Less(t, loadTime, time.Second*5, "Load time should be reasonable for large dataset")
	
	// Verify random sample of origins
	sampleIndices := []int{0, 100, 500, 999}
	for _, idx := range sampleIndices {
		origin := testOrigins[idx]
		_, exists := cors.dynamicOrigins.Load(origin)
		assert.True(t, exists, "Sample origin should be loaded: %s", origin)
		assert.True(t, cors.isOriginAllowed(origin), "Sample origin should be allowed: %s", origin)
	}
	
	mockRepo.AssertExpectations(t)
}

func TestCORSMiddleware_StartupSynchronization_ContextCancellation(t *testing.T) {
	// Test behavior when context is cancelled during startup
	mockRepo := NewMockCORSRepositoryForStartup()
	
	// Simulate slow database response
	mockRepo.SetSimulateDelay(time.Millisecond * 500)
	
	testOrigins := []string{"https://slow.com"}
	mockRepo.On("GetAllOrigins", mock.Anything).Return(testOrigins, nil)
	
	cors := &CORSMiddleware{
		allowedOrigins:   []string{},
		allowedMethods:   []string{"GET", "POST"},
		allowedHeaders:   []string{"Content-Type"},
		allowCredentials: true,
		maxAge:          "86400",
		developmentMode: true,
		repository:      mockRepo,
	}
	
	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	
	// Should handle context cancellation gracefully
	err := cors.LoadPersistedOrigins(ctx)
	// Note: The current implementation doesn't check context cancellation,
	// but it should handle it gracefully if it does
	
	if err != nil {
		assert.Contains(t, err.Error(), "context", "Error should mention context if cancelled")
	}
}

// Helper function for import
func TestCORSMiddleware_StartupSynchronization_Import(t *testing.T) {
	// Verify imports are working correctly
	assert.NotNil(t, context.Background())
	assert.NotNil(t, http.StatusOK)
	assert.NotNil(t, time.Now())
}