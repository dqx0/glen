package repository

import (
	"context"
	"time"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// WebAuthnRepository provides data access for WebAuthn credentials
type WebAuthnRepository interface {
	// Credential management
	CreateCredential(ctx context.Context, credential *models.WebAuthnCredential) error
	GetCredentialsByUserID(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error)
	GetCredentialByID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error)
	GetCredentialByTableID(ctx context.Context, id string) (*models.WebAuthnCredential, error)
	GetAllCredentials(ctx context.Context) ([]*models.WebAuthnCredential, error)
	UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error
	DeleteCredential(ctx context.Context, credentialID []byte) error
	
	// Advanced queries
	GetCredentialsByUserIDWithTransports(ctx context.Context, userID string, transports []models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error)
	UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	UpdateCredentialLastUsed(ctx context.Context, credentialID []byte, lastUsed time.Time) error
	
	// Statistics and management
	GetCredentialCount(ctx context.Context, userID string) (int, error)
	GetCredentialsByTransport(ctx context.Context, transport models.AuthenticatorTransport) ([]*models.WebAuthnCredential, error)
	
	// Health and maintenance
	CleanupExpiredCredentials(ctx context.Context, retentionPeriod time.Duration) error
	GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error)
}

// SessionStore provides data access for WebAuthn session data
type SessionStore interface {
	// Session management
	StoreSession(ctx context.Context, session *models.SessionData) error
	GetSession(ctx context.Context, sessionID string) (*models.SessionData, error)
	DeleteSession(ctx context.Context, sessionID string) error
	
	// Session cleanup and maintenance
	CleanupExpiredSessions(ctx context.Context) error
	GetActiveSessionCount(ctx context.Context) (int, error)
	GetSessionsByUserID(ctx context.Context, userID string) ([]*models.SessionData, error)
	
	// Session validation
	ValidateSessionExists(ctx context.Context, sessionID string, userID string) (bool, error)
	ExtendSessionExpiry(ctx context.Context, sessionID string, newExpiry time.Time) error
	
	// WebAuthn-specific session storage for go-webauthn library
	StoreWebAuthnSession(ctx context.Context, sessionID string, sessionData []byte) error
	GetWebAuthnSession(ctx context.Context, sessionID string) ([]byte, error)
	DeleteWebAuthnSession(ctx context.Context, sessionID string) error
}

// CredentialStatistics represents statistics about stored credentials
type CredentialStatistics struct {
	TotalCredentials         int                                           `json:"total_credentials"`
	CredentialsByTransport   map[models.AuthenticatorTransport]int       `json:"credentials_by_transport"`
	CredentialsByAttestation map[string]int                               `json:"credentials_by_attestation"`
	AvgCredentialsPerUser    float64                                      `json:"avg_credentials_per_user"`
	MostActiveUsers          []UserCredentialStats                        `json:"most_active_users"`
	CreatedInLast24Hours     int                                          `json:"created_in_last_24_hours"`
	CreatedInLastWeek        int                                          `json:"created_in_last_week"`
	CreatedInLastMonth       int                                          `json:"created_in_last_month"`
}

// UserCredentialStats represents credential statistics for a user
type UserCredentialStats struct {
	UserID           string    `json:"user_id"`
	CredentialCount  int       `json:"credential_count"`
	LastUsed         time.Time `json:"last_used"`
	TotalUsageCount  int       `json:"total_usage_count"`
}

// RepositoryConfig contains configuration for repository implementations
type RepositoryConfig struct {
	// Database connection settings
	MaxOpenConns    int           `yaml:"max_open_conns" default:"25"`
	MaxIdleConns    int           `yaml:"max_idle_conns" default:"5"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" default:"1h"`
	
	// Query timeouts
	QueryTimeout time.Duration `yaml:"query_timeout" default:"30s"`
	
	// Session settings
	SessionCleanupInterval time.Duration `yaml:"session_cleanup_interval" default:"1h"`
	MaxSessionsPerUser     int           `yaml:"max_sessions_per_user" default:"5"`
	
	// Credential retention
	CredentialRetentionPeriod time.Duration `yaml:"credential_retention_period" default:"2160h"` // 90 days
}

// RepositoryError represents repository-specific errors
type RepositoryError struct {
	Type    RepositoryErrorType `json:"type"`
	Message string              `json:"message"`
	Cause   error               `json:"cause,omitempty"`
}

// RepositoryErrorType represents the type of repository error
type RepositoryErrorType string

const (
	ErrRepositoryNotFound      RepositoryErrorType = "NOT_FOUND"
	ErrRepositoryConflict      RepositoryErrorType = "CONFLICT"
	ErrRepositoryConstraint    RepositoryErrorType = "CONSTRAINT_VIOLATION"
	ErrRepositoryConnection    RepositoryErrorType = "CONNECTION_ERROR"
	ErrRepositoryTransaction   RepositoryErrorType = "TRANSACTION_ERROR"
	ErrRepositoryTimeout       RepositoryErrorType = "TIMEOUT"
	ErrRepositoryInternal      RepositoryErrorType = "INTERNAL_ERROR"
)

// Error implements the error interface
func (e *RepositoryError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// NewRepositoryError creates a new repository error
func NewRepositoryError(errorType RepositoryErrorType, message string, cause error) *RepositoryError {
	return &RepositoryError{
		Type:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// IsRepositoryError checks if an error is a repository error
func IsRepositoryError(err error) bool {
	_, ok := err.(*RepositoryError)
	return ok
}

// GetRepositoryError extracts repository error from an error
func GetRepositoryError(err error) *RepositoryError {
	if repoErr, ok := err.(*RepositoryError); ok {
		return repoErr
	}
	return nil
}

// Common repository errors
var (
	ErrCredentialNotFound = NewRepositoryError(ErrRepositoryNotFound, "credential not found", nil)
	ErrSessionNotFound    = NewRepositoryError(ErrRepositoryNotFound, "session not found", nil)
	ErrDuplicateCredential = NewRepositoryError(ErrRepositoryConflict, "credential already exists", nil)
)