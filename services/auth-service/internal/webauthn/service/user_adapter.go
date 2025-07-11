package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// UserService represents the interface for user data retrieval
type UserService interface {
	GetUserByID(ctx context.Context, userID string) (*UserInfo, error)
	GetUserByUsername(ctx context.Context, username string) (*UserInfo, error)
	CreateUser(ctx context.Context, username, email string) (*UserInfo, error)
}

// UserInfo represents basic user information
type UserInfo struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email,omitempty"`
}

// WebAuthnUserAdapter adapts user data for go-webauthn library
type WebAuthnUserAdapter struct {
	userInfo    *UserInfo
	credentials []webauthn.Credential
}

// NewWebAuthnUserAdapter creates a new user adapter
func NewWebAuthnUserAdapter(userInfo *UserInfo, credentials []*models.WebAuthnCredential) *WebAuthnUserAdapter {
	webauthnCreds := make([]webauthn.Credential, len(credentials))
	for i, cred := range credentials {
		webauthnCreds[i] = convertToWebAuthnCredential(cred)
	}

	return &WebAuthnUserAdapter{
		userInfo:    userInfo,
		credentials: webauthnCreds,
	}
}

// WebAuthnID returns the user's WebAuthn ID (required by go-webauthn)
func (u *WebAuthnUserAdapter) WebAuthnID() []byte {
	return []byte(u.userInfo.ID)
}

// WebAuthnName returns the user's WebAuthn name (required by go-webauthn)
func (u *WebAuthnUserAdapter) WebAuthnName() string {
	return u.userInfo.Username
}

// WebAuthnDisplayName returns the user's display name (required by go-webauthn)
func (u *WebAuthnUserAdapter) WebAuthnDisplayName() string {
	if u.userInfo.DisplayName != "" {
		return u.userInfo.DisplayName
	}
	return u.userInfo.Username
}

// WebAuthnIcon returns the user's icon URL (optional)
func (u *WebAuthnUserAdapter) WebAuthnIcon() string {
	// Could be implemented to return user avatar URL
	return ""
}

// WebAuthnCredentials returns the user's WebAuthn credentials (required by go-webauthn)
func (u *WebAuthnUserAdapter) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// convertToWebAuthnCredential converts models.WebAuthnCredential to webauthn.Credential
func convertToWebAuthnCredential(cred *models.WebAuthnCredential) webauthn.Credential {
	return webauthn.Credential{
		ID:        cred.CredentialID,
		PublicKey: cred.PublicKey,
		AttestationType: cred.AttestationType,
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte{}, // Would need to be extracted from attestation
			SignCount:    cred.SignCount,
			CloneWarning: cred.CloneWarning,
		},
	}
}

// MockUserService provides a mock implementation for testing/development
type MockUserService struct {
	users map[string]*UserInfo
}

// NewMockUserService creates a new mock user service
func NewMockUserService() *MockUserService {
	return &MockUserService{
		users: make(map[string]*UserInfo),
	}
}

// AddUser adds a user to the mock service
func (m *MockUserService) AddUser(user *UserInfo) {
	m.users[user.ID] = user
}

// GetUserByID returns a user by ID
func (m *MockUserService) GetUserByID(ctx context.Context, userID string) (*UserInfo, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", userID)
	}
	return user, nil
}

// GetUserByUsername returns a user by username
func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*UserInfo, error) {
	fmt.Printf("[DEBUG] MockUserService: Looking up user: %s\n", username)
	for _, user := range m.users {
		if user.Username == username {
			fmt.Printf("[DEBUG] MockUserService: Found user: %+v\n", user)
			return user, nil
		}
	}
	fmt.Printf("[DEBUG] MockUserService: User not found: %s\n", username)
	return nil, fmt.Errorf("user not found: %s", username)
}

// CreateUser creates a new mock user
func (m *MockUserService) CreateUser(ctx context.Context, username, email string) (*UserInfo, error) {
	// Check if user already exists
	for _, user := range m.users {
		if user.Username == username {
			return nil, fmt.Errorf("user already exists: %s", username)
		}
	}
	
	// Create new user
	newUser := &UserInfo{
		ID:          fmt.Sprintf("auto-%d", len(m.users)+1000),
		Username:    username,
		DisplayName: username,
		Email:       email,
	}
	
	m.AddUser(newUser)
	return newUser, nil
}

// CreateDefaultMockUsers creates some default users for testing
func CreateDefaultMockUsers() *MockUserService {
	fmt.Printf("[INIT] Creating MockUserService with default test users\n")
	mockService := NewMockUserService()
	
	// Add some default test users
	mockService.AddUser(&UserInfo{
		ID:          "user-123",
		Username:    "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
	})
	
	mockService.AddUser(&UserInfo{
		ID:          "admin-456",
		Username:    "admin",
		DisplayName: "Administrator",
		Email:       "admin@example.com",
	})
	
	fmt.Printf("[INIT] MockUserService created with users: testuser, admin\n")
	return mockService
}

// DatabaseUserService provides user lookup from the database
type DatabaseUserService struct {
	db *sql.DB
}

// NewDatabaseUserService creates a new database user service
func NewDatabaseUserService(db *sql.DB) *DatabaseUserService {
	fmt.Printf("[INIT] Creating DatabaseUserService with database connection\n")
	return &DatabaseUserService{db: db}
}

// GetUserByID looks up a user by their ID
func (d *DatabaseUserService) GetUserByID(ctx context.Context, userID string) (*UserInfo, error) {
	var user UserInfo
	query := `SELECT id, username, COALESCE(email, '') as email, username as display_name 
	          FROM users WHERE id = $1 AND status = 'active'`
	
	err := d.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.DisplayName)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", userID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}
	
	return &user, nil
}

// GetUserByUsername looks up a user by their username
func (d *DatabaseUserService) GetUserByUsername(ctx context.Context, username string) (*UserInfo, error) {
	var user UserInfo
	query := `SELECT id, username, COALESCE(email, '') as email, username as display_name 
	          FROM users WHERE username = $1 AND status = 'active'`
	
	fmt.Printf("[DEBUG] Looking up user: %s with query: %s\n", username, query)
	
	err := d.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.DisplayName)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("[DEBUG] User not found: %s\n", username)
			return nil, fmt.Errorf("user not found: %s", username)
		}
		fmt.Printf("[DEBUG] Database error for user %s: %v\n", username, err)
		return nil, fmt.Errorf("database error: %w", err)
	}
	
	fmt.Printf("[DEBUG] Found user: %+v\n", user)
	return &user, nil
}

// CreateUser creates a new user account
func (d *DatabaseUserService) CreateUser(ctx context.Context, username, email string) (*UserInfo, error) {
	query := `INSERT INTO users (username, email, email_verified, status, created_at, updated_at) 
	          VALUES ($1, $2, true, 'active', NOW(), NOW()) 
	          RETURNING id, username, COALESCE(email, '') as email, username as display_name`
	
	var user UserInfo
	err := d.db.QueryRowContext(ctx, query, username, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.DisplayName)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	
	return &user, nil
}

// UserCredentialManager manages the relationship between users and their credentials
type UserCredentialManager struct {
	userService UserService
	credRepo    WebAuthnRepository
}

// NewUserCredentialManager creates a new user credential manager
func NewUserCredentialManager(userService UserService, credRepo WebAuthnRepository) *UserCredentialManager {
	return &UserCredentialManager{
		userService: userService,
		credRepo:    credRepo,
	}
}

// GetUserWithCredentials retrieves user info and their WebAuthn credentials
func (m *UserCredentialManager) GetUserWithCredentials(ctx context.Context, userID string) (*WebAuthnUserAdapter, error) {
	// Get user info
	userInfo, err := m.userService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Get user's credentials
	credentials, err := m.credRepo.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	return NewWebAuthnUserAdapter(userInfo, credentials), nil
}

// GetUserByUsernameWithCredentials retrieves user by username and their WebAuthn credentials
func (m *UserCredentialManager) GetUserByUsernameWithCredentials(ctx context.Context, username string) (*WebAuthnUserAdapter, error) {
	// Get user info by username
	userInfo, err := m.userService.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Get user's credentials
	credentials, err := m.credRepo.GetCredentialsByUserID(ctx, userInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	return NewWebAuthnUserAdapter(userInfo, credentials), nil
}

// WebAuthnRepository interface is imported here to avoid circular imports
type WebAuthnRepository interface {
	GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error)
}