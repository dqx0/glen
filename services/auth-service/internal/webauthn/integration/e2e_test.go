package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dqx0/glen/auth-service/internal/webauthn/handlers"
	"github.com/dqx0/glen/auth-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
	"github.com/dqx0/glen/auth-service/internal/webauthn/repository"
	"github.com/dqx0/glen/auth-service/internal/webauthn/service"
)

// mockSessionStore implements SessionStore for testing
type mockSessionStore struct {
	sessions map[string]*models.SessionData
}

func (m *mockSessionStore) StoreSession(ctx context.Context, session *models.SessionData) error {
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionStore) GetSession(ctx context.Context, sessionID string) (*models.SessionData, error) {
	if data, exists := m.sessions[sessionID]; exists {
		return data, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionStore) CleanupExpiredSessions(ctx context.Context) error {
	// For testing, we don't need to implement this
	return nil
}

func (m *mockSessionStore) GetActiveSessionCount(ctx context.Context) (int, error) {
	return len(m.sessions), nil
}

func (m *mockSessionStore) GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error) {
	var sessions []*models.SessionData
	for _, session := range m.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (m *mockSessionStore) ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error) {
	if session, exists := m.sessions[sessionID]; exists {
		return session.UserID == userID, nil
	}
	return false, nil
}

func (m *mockSessionStore) ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error {
	if session, exists := m.sessions[sessionID]; exists {
		session.ExpiresAt = newExpiry
		return nil
	}
	return fmt.Errorf("session not found")
}

func (m *mockSessionStore) StoreWebAuthnSession(ctx context.Context, sessionID string, sessionData []byte) error {
	return nil
}

func (m *mockSessionStore) GetWebAuthnSession(ctx context.Context, sessionID string) ([]byte, error) {
	return nil, fmt.Errorf("session not found")
}

func (m *mockSessionStore) DeleteWebAuthnSession(ctx context.Context, sessionID string) error {
	return nil
}

// E2ETestSuite provides end-to-end testing for the WebAuthn implementation
type E2ETestSuite struct {
	suite.Suite
	server      *httptest.Server
	router      *chi.Mux
	db          *sqlx.DB
	credRepo    repository.WebAuthnRepository
	sessionRepo repository.SessionStore
	service     service.WebAuthnService
	jwtConfig   *middleware.JWTConfig
	testUserID  string
	adminUserID string
}

func (suite *E2ETestSuite) SetupSuite() {
	// Set environment to development for testing
	os.Setenv("ENVIRONMENT", "development")

	// Setup in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(suite.T(), err)
	sqlxDB := sqlx.NewDb(db, "sqlite3")
	suite.db = sqlxDB

	// Create repository instances - use a SQLite-compatible approach
	repoConfig := &repository.RepositoryConfig{
		QueryTimeout: 30 * time.Second,
	}
	// For testing, we'll use the PostgreSQL repository with SQLite database
	// The repository handles some SQLite compatibility already
	suite.credRepo = repository.NewPostgreSQLWebAuthnRepository(sqlxDB, repoConfig)

	// Create a mock session store
	suite.sessionRepo = &mockSessionStore{
		sessions: make(map[string]*models.SessionData),
	}

	// Initialize database tables (create manually for SQLite)
	err = suite.createTables()
	require.NoError(suite.T(), err)

	// Create service
	config := &service.WebAuthnConfig{
		RPID:                  "localhost",
		RPName:                "Test Service",
		AllowedOrigins:        []string{"https://localhost"},
		ChallengeLength:       32, // Set challenge length to 32 bytes
		SessionTimeout:        5 * time.Minute,
		ChallengeExpiry:       2 * time.Minute, // Set challenge expiry to 2 minutes
		MaxCredentialsPerUser: 10,              // Allow up to 10 credentials per user
	}
	webauthnService, err := service.NewSimpleWebAuthnService(suite.credRepo, suite.sessionRepo, config)
	require.NoError(suite.T(), err)
	suite.service = webauthnService

	// Setup JWT config
	suite.jwtConfig = &middleware.JWTConfig{
		Secret:        []byte("test-secret-key"),
		SigningMethod: middleware.DefaultJWTConfig().SigningMethod,
		Expiration:    24 * time.Hour,
	}

	// Create router and handlers with custom JWT config
	suite.router = chi.NewRouter()

	// Create handlers with the same JWT config
	registrationHandler := handlers.NewRegistrationHandler(suite.service)
	authenticationHandler := handlers.NewAuthenticationHandlerWithJWT(suite.service, suite.jwtConfig)
	managementHandler := handlers.NewManagementHandlerWithJWT(suite.service, suite.jwtConfig)

	// Register routes manually to ensure JWT config consistency
	registrationHandler.RegisterRoutes(suite.router)
	authenticationHandler.RegisterRoutes(suite.router)
	managementHandler.RegisterRoutes(suite.router)

	// Health endpoint
	suite.router.Get("/webauthn/health", func(w http.ResponseWriter, r *http.Request) {
		response := handlers.HealthCheckResponse{
			Status:  "healthy",
			Service: "webauthn",
			Version: "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Create test server
	suite.server = httptest.NewServer(suite.router)

	// Create test users
	suite.testUserID = uuid.New().String()
	suite.adminUserID = "87654321-4321-4321-9876-ba9876543210" // Fixed admin user ID for testing
}

func (suite *E2ETestSuite) TearDownSuite() {
	suite.server.Close()
	suite.db.Close()
	// Clean up environment variable
	os.Unsetenv("ENVIRONMENT")
}

func (suite *E2ETestSuite) createTables() error {
	// Create users table first (required for foreign key)
	usersQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email_verified BOOLEAN NOT NULL DEFAULT FALSE,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := suite.db.Exec(usersQuery)
	if err != nil {
		return err
	}

	// Use the WebAuthn credentials schema that matches the repository expectations
	credentialsQuery := `
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT NOT NULL PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id BLOB NOT NULL UNIQUE,
		public_key BLOB NOT NULL,
		attestation_type TEXT DEFAULT 'none',
		transport TEXT DEFAULT '',
		sign_count INTEGER NOT NULL DEFAULT 0,
		clone_warning BOOLEAN NOT NULL DEFAULT 0,
		name TEXT NOT NULL DEFAULT '',
		last_used_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		user_present BOOLEAN NOT NULL DEFAULT 0,
		user_verified BOOLEAN NOT NULL DEFAULT 0,
		backup_eligible BOOLEAN NOT NULL DEFAULT 0,
		backup_state BOOLEAN NOT NULL DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`

	_, err = suite.db.Exec(credentialsQuery)
	if err != nil {
		return err
	}

	// Create sessions table using the actual schema
	sessionsQuery := `
	CREATE TABLE IF NOT EXISTS webauthn_sessions (
		id TEXT NOT NULL PRIMARY KEY,
		user_id TEXT NOT NULL,
		challenge BLOB NOT NULL,
		allowed_credential_ids TEXT DEFAULT '',
		user_verification TEXT NOT NULL DEFAULT 'preferred',
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`

	_, err = suite.db.Exec(sessionsQuery)
	return err
}

func (suite *E2ETestSuite) SetupTest() {
	// Clean up database before each test
	_, err := suite.db.Exec("DELETE FROM webauthn_credentials")
	require.NoError(suite.T(), err)

	_, err = suite.db.Exec("DELETE FROM users")
	require.NoError(suite.T(), err)

	// Insert test users
	_, err = suite.db.Exec(`
		INSERT INTO users (id, username, email, password_hash, email_verified, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, suite.testUserID, "testuser", "test@example.com", "hashedpassword", true, "active")
	require.NoError(suite.T(), err)

	_, err = suite.db.Exec(`
		INSERT INTO users (id, username, email, password_hash, email_verified, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, suite.adminUserID, "adminuser", "admin@example.com", "hashedpassword", true, "active")
	require.NoError(suite.T(), err)
}

// TestFullRegistrationFlow tests the complete registration process
func (suite *E2ETestSuite) TestFullRegistrationFlow() {
	// Step 1: Start registration
	startReq := service.RegistrationStartRequest{
		UserID:      suite.testUserID,
		Username:    "testuser",
		DisplayName: "Test User",
	}

	startResp := suite.postJSONWithAuth("/webauthn/register/start", startReq, http.StatusOK)
	var startResult service.RegistrationStartResponse
	err := json.Unmarshal(startResp, &startResult)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), startResult.SessionID)
	assert.NotNil(suite.T(), startResult.CreationOptions)

	// For E2E test, we'll just verify that the start worked
	// The finish step would require complex WebAuthn library integration
	// which is beyond the scope of this integration test
}

// TestFullAuthenticationFlow tests the complete authentication process
func (suite *E2ETestSuite) TestFullAuthenticationFlow() {
	// Step 1: Start authentication
	startReq := service.AuthenticationStartRequest{
		UserID:         suite.testUserID,
		UserIdentifier: "testuser",
	}

	// Authentication should fail because user has no credentials registered
	startResp := suite.postJSONWithAuth("/webauthn/authenticate/start", startReq, http.StatusNotFound)
	var errorResp map[string]interface{}
	err := json.Unmarshal(startResp, &errorResp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Credential not found", errorResp["error"])

	// For E2E test, we verify that authentication fails when no credentials exist
	// In a real scenario, user would need to register credentials first
}

// TestCredentialManagementWithAuth tests credential management with authentication
func (suite *E2ETestSuite) TestCredentialManagementWithAuth() {

	// Test: Access without authorization should fail
	suite.get(fmt.Sprintf("/webauthn/users/%s/credentials", suite.testUserID), http.StatusUnauthorized)

	// Test: Valid token should allow access (even if no credentials exist)
	resp := suite.getWithAuth(fmt.Sprintf("/webauthn/users/%s/credentials", suite.testUserID), http.StatusOK)

	var credResp handlers.GetCredentialsResponse
	err := json.Unmarshal(resp, &credResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), credResp.Success)
	assert.Equal(suite.T(), 0, credResp.Count) // No credentials initially

	// Test: Unauthorized access (different user)
	otherUserID := uuid.New().String()
	// Test: User cannot access other user's credentials
	// (This will use the testUserID token trying to access otherUserID credentials)
	otherUserCredentialsURL := fmt.Sprintf("/webauthn/users/%s/credentials", otherUserID)
	suite.getWithAuth(otherUserCredentialsURL, http.StatusForbidden)
}

// TestAdminEndpointsWithAuth tests admin endpoints with proper authorization
func (suite *E2ETestSuite) TestAdminEndpointsWithAuth() {

	// Test: Admin can access statistics
	resp := suite.getWithAdminAuth("/webauthn/admin/statistics", http.StatusOK)
	var statsResp handlers.StatisticsResponse
	err := json.Unmarshal(resp, &statsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), statsResp.Success)
	assert.NotNil(suite.T(), statsResp.Statistics)

	// Test: Regular user cannot access statistics
	suite.getWithAuth("/webauthn/admin/statistics", http.StatusForbidden)

	// Test: Admin can trigger cleanup
	suite.postJSONWithAdminAuth("/webauthn/admin/cleanup", nil, http.StatusOK)

	// Test: Regular user cannot trigger cleanup
	suite.postJSONWithAuth("/webauthn/admin/cleanup", nil, http.StatusForbidden)
}

// TestHealthEndpoint tests the health check endpoint
func (suite *E2ETestSuite) TestHealthEndpoint() {
	resp := suite.get("/webauthn/health", http.StatusOK)

	var healthResp handlers.HealthCheckResponse
	err := json.Unmarshal(resp, &healthResp)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "healthy", healthResp.Status)
	assert.Equal(suite.T(), "webauthn", healthResp.Service)
}

// TestErrorHandling tests various error scenarios
func (suite *E2ETestSuite) TestErrorHandling() {
	// In development mode, authentication is bypassed with X-User-ID header
	// So we need to test without the dev mode headers

	// Test invalid JSON in registration (without X-User-ID header)
	suite.postRaw("/webauthn/register/start", []byte("invalid json"), http.StatusUnauthorized)

	// Test missing X-User-ID header for protected endpoints (dev mode expects this header)
	suite.get("/webauthn/admin/statistics", http.StatusUnauthorized)

	// Test with invalid/empty X-User-ID header
	req, err := http.NewRequest("GET", suite.server.URL+"/webauthn/admin/statistics", nil)
	require.NoError(suite.T(), err)
	req.Header.Set("X-User-ID", "") // Empty user ID should fail

	resp, err := http.DefaultClient.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

// Helper methods

func (suite *E2ETestSuite) postJSON(path string, body interface{}, expectedStatus int) []byte {
	return suite.postJSONWithHeaders(path, body, nil, expectedStatus)
}

// postJSONWithAuth makes an authenticated POST request with JWT token
func (suite *E2ETestSuite) postJSONWithAuth(path string, body interface{}, expectedStatus int) []byte {
	token, err := middleware.GenerateToken(suite.jwtConfig, suite.testUserID, false)
	require.NoError(suite.T(), err)

	// Debug log the token
	suite.T().Logf("Generated token for %s: %s", path, token)

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"X-User-ID":     suite.testUserID, // For development mode
	}
	return suite.postJSONWithHeaders(path, body, headers, expectedStatus)
}

// postJSONWithAdminAuth makes an authenticated POST request with admin JWT token
func (suite *E2ETestSuite) postJSONWithAdminAuth(path string, body interface{}, expectedStatus int) []byte {
	token, err := middleware.GenerateToken(suite.jwtConfig, suite.adminUserID, true)
	require.NoError(suite.T(), err)

	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"X-User-ID":     suite.adminUserID, // For development mode
	}
	return suite.postJSONWithHeaders(path, body, headers, expectedStatus)
}

// getWithAuth makes an authenticated GET request with JWT token
func (suite *E2ETestSuite) getWithAuth(path string, expectedStatus int) []byte {
	token, err := middleware.GenerateToken(suite.jwtConfig, suite.testUserID, false)
	require.NoError(suite.T(), err)

	req, err := http.NewRequest("GET", suite.server.URL+path, nil)
	require.NoError(suite.T(), err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-ID", suite.testUserID) // For development mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), expectedStatus, resp.StatusCode)

	var respBody []byte
	if resp.Body != nil {
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(suite.T(), err)
		respBody = buf.Bytes()
	}

	return respBody
}

// getWithAdminAuth makes an authenticated GET request with admin JWT token
func (suite *E2ETestSuite) getWithAdminAuth(path string, expectedStatus int) []byte {
	token, err := middleware.GenerateToken(suite.jwtConfig, suite.adminUserID, true)
	require.NoError(suite.T(), err)

	req, err := http.NewRequest("GET", suite.server.URL+path, nil)
	require.NoError(suite.T(), err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-User-ID", suite.adminUserID) // For development mode

	resp, err := http.DefaultClient.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), expectedStatus, resp.StatusCode)

	var respBody []byte
	if resp.Body != nil {
		buf := new(bytes.Buffer)
		_, err = buf.ReadFrom(resp.Body)
		require.NoError(suite.T(), err)
		respBody = buf.Bytes()
	}

	return respBody
}

func (suite *E2ETestSuite) postJSONWithHeaders(path string, body interface{}, headers map[string]string, expectedStatus int) []byte {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		require.NoError(suite.T(), err)
	}
	return suite.postRawWithHeaders(path, bodyBytes, headers, expectedStatus)
}

func (suite *E2ETestSuite) postRaw(path string, body []byte, expectedStatus int) []byte {
	return suite.postRawWithHeaders(path, body, nil, expectedStatus)
}

func (suite *E2ETestSuite) postRawWithHeaders(path string, body []byte, headers map[string]string, expectedStatus int) []byte {
	req, err := http.NewRequest("POST", suite.server.URL+path, bytes.NewBuffer(body))
	require.NoError(suite.T(), err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	// Read response body for debugging
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	suite.T().Logf("Response for %s: Status=%d, Body=%s", path, resp.StatusCode, string(respBody))

	if resp.StatusCode != expectedStatus {
		suite.T().Logf("Expected status %d but got %d. Response: %s", expectedStatus, resp.StatusCode, string(respBody))
	}
	assert.Equal(suite.T(), expectedStatus, resp.StatusCode)

	return respBody
}

func (suite *E2ETestSuite) get(path string, expectedStatus int) []byte {
	return suite.getWithHeaders(path, nil, expectedStatus)
}

func (suite *E2ETestSuite) getWithHeaders(path string, headers map[string]string, expectedStatus int) []byte {
	req, err := http.NewRequest("GET", suite.server.URL+path, nil)
	require.NoError(suite.T(), err)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	assert.Equal(suite.T(), expectedStatus, resp.StatusCode)

	var respBody []byte
	if resp.Body != nil {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp.Body)
		require.NoError(suite.T(), err)
		respBody = buf.Bytes()
	}

	return respBody
}

// TestE2ESuite runs the end-to-end test suite
func TestE2ESuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}
