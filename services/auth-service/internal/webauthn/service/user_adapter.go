package service

import (
	"context"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// UserService represents the interface for user data retrieval
type UserService interface {
	GetUserByID(ctx context.Context, userID string) (*UserInfo, error)
	GetUserByUsername(ctx context.Context, username string) (*UserInfo, error)
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
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found: %s", username)
}

// CreateDefaultMockUsers creates some default users for testing
func CreateDefaultMockUsers() *MockUserService {
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
	
	return mockService
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