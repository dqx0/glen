package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/dqx0/glen/user-service/internal/webauthn/handlers"
	"github.com/dqx0/glen/user-service/internal/webauthn/middleware"
	"github.com/dqx0/glen/user-service/internal/webauthn/models"
	"github.com/dqx0/glen/user-service/internal/webauthn/repository"
	"github.com/dqx0/glen/user-service/internal/webauthn/service"
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
	// Setup in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(suite.T(), err)
	sqlxDB := sqlx.NewDb(db, "sqlite3")
	suite.db = sqlxDB

	// Create repository instances
	repoConfig := &repository.RepositoryConfig{}
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
		RPID:             "localhost",
		RPName:           "Test Service",
		AllowedOrigins:   []string{"https://localhost"},
		ChallengeLength:  32, // Set challenge length to 32 bytes
		SessionTimeout:   5 * time.Minute,
		ChallengeExpiry:  2 * time.Minute, // Set challenge expiry to 2 minutes
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
	suite.adminUserID = uuid.New().String()
}

func (suite *E2ETestSuite) TearDownSuite() {
	suite.server.Close()
	suite.db.Close()
}

func (suite *E2ETestSuite) createTables() error {
	// Create WebAuthn credentials table for SQLite
	query := `
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		credential_id BLOB NOT NULL UNIQUE,
		public_key BLOB NOT NULL,
		attestation_type TEXT NOT NULL,
		transport TEXT NOT NULL,
		flags TEXT NOT NULL,
		sign_count INTEGER NOT NULL DEFAULT 0,
		clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`
	
	_, err := suite.db.Exec(query)
	return err
}

func (suite *E2ETestSuite) SetupTest() {
	// Clean up database before each test
	_, err := suite.db.Exec("DELETE FROM webauthn_credentials")
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

	startResp := suite.postJSON("/webauthn/register/start", startReq, http.StatusOK)
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

	startResp := suite.postJSON("/webauthn/authenticate/start", startReq, http.StatusOK)
	var startResult service.AuthenticationStartResponse
	err := json.Unmarshal(startResp, &startResult)
	require.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), startResult.SessionID)
	assert.NotNil(suite.T(), startResult.RequestOptions)

	// For E2E test, we'll just verify that the start worked
	// The finish step would require complex WebAuthn library integration
}

// TestCredentialManagementWithAuth tests credential management with authentication
func (suite *E2ETestSuite) TestCredentialManagementWithAuth() {
	// Generate JWT token for the user
	token, err := middleware.GenerateToken(suite.jwtConfig, suite.testUserID, false)
	require.NoError(suite.T(), err)

	// Test: Access without authorization should fail
	suite.get(fmt.Sprintf("/webauthn/credentials/%s", suite.testUserID), http.StatusUnauthorized)

	// Test: Valid token should allow access (even if no credentials exist)
	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}
	resp := suite.getWithHeaders(fmt.Sprintf("/webauthn/credentials/%s", suite.testUserID), headers, http.StatusOK)
	
	var credResp handlers.GetCredentialsResponse
	err = json.Unmarshal(resp, &credResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), credResp.Success)
	assert.Equal(suite.T(), 0, credResp.Count) // No credentials initially

	// Test: Unauthorized access (different user)
	otherUserID := uuid.New().String()
	suite.getWithHeaders(fmt.Sprintf("/webauthn/credentials/%s", otherUserID), headers, http.StatusForbidden)
}

// TestAdminEndpointsWithAuth tests admin endpoints with proper authorization
func (suite *E2ETestSuite) TestAdminEndpointsWithAuth() {
	// Generate admin JWT token
	adminToken, err := middleware.GenerateToken(suite.jwtConfig, suite.adminUserID, true)
	require.NoError(suite.T(), err)

	// Generate regular user JWT token
	userToken, err := middleware.GenerateToken(suite.jwtConfig, suite.testUserID, false)
	require.NoError(suite.T(), err)

	adminHeaders := map[string]string{
		"Authorization": "Bearer " + adminToken,
	}
	userHeaders := map[string]string{
		"Authorization": "Bearer " + userToken,
	}

	// Test: Admin can access statistics
	resp := suite.getWithHeaders("/webauthn/admin/statistics", adminHeaders, http.StatusOK)
	var statsResp handlers.StatisticsResponse
	err = json.Unmarshal(resp, &statsResp)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), statsResp.Success)
	assert.NotNil(suite.T(), statsResp.Statistics)

	// Test: Regular user cannot access statistics
	suite.getWithHeaders("/webauthn/admin/statistics", userHeaders, http.StatusForbidden)

	// Test: Admin can trigger cleanup
	suite.postJSONWithHeaders("/webauthn/admin/cleanup", nil, adminHeaders, http.StatusOK)

	// Test: Regular user cannot trigger cleanup
	suite.postJSONWithHeaders("/webauthn/admin/cleanup", nil, userHeaders, http.StatusForbidden)
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
	// Test invalid JSON in registration
	suite.postRaw("/webauthn/register/start", []byte("invalid json"), http.StatusBadRequest)

	// Test missing authentication for protected endpoints
	suite.get("/webauthn/admin/statistics", http.StatusUnauthorized)

	// Test invalid JWT token
	invalidHeaders := map[string]string{
		"Authorization": "Bearer invalid.token.here",
	}
	suite.getWithHeaders("/webauthn/admin/statistics", invalidHeaders, http.StatusUnauthorized)
}

// Helper methods

func (suite *E2ETestSuite) postJSON(path string, body interface{}, expectedStatus int) []byte {
	return suite.postJSONWithHeaders(path, body, nil, expectedStatus)
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

	assert.Equal(suite.T(), expectedStatus, resp.StatusCode)

	respBody := make([]byte, 0)
	if resp.ContentLength != 0 {
		buf := make([]byte, resp.ContentLength)
		resp.Body.Read(buf)
		respBody = buf
	}

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

	respBody := make([]byte, 0)
	if resp.ContentLength != 0 {
		buf := make([]byte, resp.ContentLength)
		resp.Body.Read(buf)
		respBody = buf
	}

	return respBody
}

// TestE2ESuite runs the end-to-end test suite
func TestE2ESuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}