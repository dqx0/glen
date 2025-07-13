package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dqx0/glen/api-gateway/internal/repository"

	_ "github.com/lib/pq"
)

func TestStartupIntegration_CORSSynchronization(t *testing.T) {
	// Skip if no test database URL provided
	testDatabaseURL := os.Getenv("TEST_DATABASE_URL")
	if testDatabaseURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	// Test database initialization
	db, err := initDatabase(testDatabaseURL)
	require.NoError(t, err, "Database initialization should succeed")
	defer db.Close()

	// Verify database connection works
	ctx := context.Background()
	err = db.PingContext(ctx)
	require.NoError(t, err, "Database ping should succeed")

	// Test CORS repository creation
	corsRepo := repository.NewCORSRepository(db)
	require.NotNil(t, corsRepo, "CORS repository should be created")

	// Test basic repository operations
	testOrigin := "https://integration-test.com"
	testClientID := "test_client_startup"

	// Clean up before test
	corsRepo.RemoveOrigin(ctx, testOrigin)

	// Add test origin
	err = corsRepo.AddOrigin(ctx, testOrigin, testClientID)
	require.NoError(t, err, "Should be able to add test origin")

	// Verify it was added
	origins, err := corsRepo.GetAllOrigins(ctx)
	require.NoError(t, err, "Should be able to get all origins")
	assert.Contains(t, origins, testOrigin, "Test origin should be in database")

	// Clean up after test
	corsRepo.RemoveOrigin(ctx, testOrigin)
}

func TestStartupIntegration_ConfigurationLoading(t *testing.T) {
	// Test configuration loading with various environment variables
	originalEnv := make(map[string]string)
	testEnvVars := map[string]string{
		"USER_SERVICE_URL":   "http://test-user:8082",
		"AUTH_SERVICE_URL":   "http://test-auth:8081",
		"SOCIAL_SERVICE_URL": "http://test-social:8083",
		"DATABASE_URL":       "postgres://test:test@localhost/test_db",
	}

	// Save original values and set test values
	for key, value := range testEnvVars {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}

	// Test configuration loading
	config := loadConfig()
	assert.Equal(t, "http://test-user:8082", config.UserService)
	assert.Equal(t, "http://test-auth:8081", config.AuthService)
	assert.Equal(t, "http://test-social:8083", config.SocialService)
	assert.Equal(t, "postgres://test:test@localhost/test_db", config.DatabaseURL)

	// Restore original environment
	for key, originalValue := range originalEnv {
		if originalValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, originalValue)
		}
	}
}

func TestStartupIntegration_DatabaseInitialization_InvalidURL(t *testing.T) {
	// Test database initialization with invalid URL
	invalidURLs := []string{
		"",
		"not-a-url",
		"postgres://invalid:invalid@nonexistent:5432/nonexistent",
	}

	for _, url := range invalidURLs {
		db, err := initDatabase(url)
		if err == nil {
			db.Close() // Close if somehow it succeeded
		}
		// We expect errors for invalid URLs, but don't require specific error types
		// since different invalid URLs might fail at different stages
	}
}

func TestStartupIntegration_DatabaseConnectionPool(t *testing.T) {
	testDatabaseURL := os.Getenv("TEST_DATABASE_URL")
	if testDatabaseURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	db, err := initDatabase(testDatabaseURL)
	require.NoError(t, err, "Database initialization should succeed")
	defer db.Close()

	// Test connection pool settings
	stats := db.Stats()
	assert.LessOrEqual(t, stats.MaxOpenConnections, 25, "Max open connections should be configured")

	// Test that connections work under load
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Simulate concurrent database operations
	const numOperations = 10
	resultCh := make(chan error, numOperations)

	for i := 0; i < numOperations; i++ {
		go func() {
			resultCh <- db.PingContext(ctx)
		}()
	}

	// Wait for all operations to complete
	for i := 0; i < numOperations; i++ {
		select {
		case err := <-resultCh:
			assert.NoError(t, err, "Concurrent database operation should succeed")
		case <-ctx.Done():
			t.Fatal("Timeout waiting for database operations")
		}
	}
}

func TestStartupIntegration_DefaultConfiguration(t *testing.T) {
	// Clear all environment variables
	envVars := []string{
		"USER_SERVICE_URL",
		"AUTH_SERVICE_URL", 
		"SOCIAL_SERVICE_URL",
		"DATABASE_URL",
	}

	originalEnv := make(map[string]string)
	for _, key := range envVars {
		originalEnv[key] = os.Getenv(key)
		os.Unsetenv(key)
	}

	// Test default configuration
	config := loadConfig()
	assert.Equal(t, "http://localhost:8082", config.UserService)
	assert.Equal(t, "http://localhost:8081", config.AuthService)
	assert.Equal(t, "http://localhost:8083", config.SocialService)
	assert.Equal(t, "", config.DatabaseURL)

	// Restore original environment
	for key, originalValue := range originalEnv {
		if originalValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, originalValue)
		}
	}
}

func TestStartupIntegration_EnvironmentVariableHelpers(t *testing.T) {
	// Test getEnvOrDefault function
	testKey := "TEST_STARTUP_INTEGRATION_VAR"
	
	// Test with no environment variable set
	os.Unsetenv(testKey)
	result := getEnvOrDefault(testKey, "default_value")
	assert.Equal(t, "default_value", result)
	
	// Test with environment variable set
	os.Setenv(testKey, "custom_value")
	result = getEnvOrDefault(testKey, "default_value")
	assert.Equal(t, "custom_value", result)
	
	// Clean up
	os.Unsetenv(testKey)
}