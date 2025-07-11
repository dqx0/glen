package service

import (
	"context"
	"fmt"
	"time"

	"github.com/dqx0/glen/auth-service/internal/webauthn/models"
)

// WebAuthnService provides business logic for WebAuthn operations
type WebAuthnService interface {
	// Registration flow
	BeginRegistration(ctx context.Context, req *RegistrationStartRequest) (*RegistrationStartResponse, error)
	FinishRegistration(ctx context.Context, req *RegistrationFinishRequest) (*RegistrationResult, error)
	
	// Authentication flow
	BeginAuthentication(ctx context.Context, req *AuthenticationStartRequest) (*AuthenticationStartResponse, error)
	FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (*AuthenticationResult, error)
	
	// Credential management
	GetUserCredentials(ctx context.Context, userID string) ([]*models.WebAuthnCredential, error)
	UpdateCredential(ctx context.Context, credential *models.WebAuthnCredential) error
	DeleteCredential(ctx context.Context, userID string, credentialID []byte) error
	
	// Advanced operations
	GetCredentialStatistics(ctx context.Context) (*CredentialStatistics, error)
	CleanupExpiredData(ctx context.Context) error
	ValidateCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error
}

// ChallengeManager manages WebAuthn challenges and session data
type ChallengeManager interface {
	// Challenge generation and validation
	GenerateChallenge(ctx context.Context) ([]byte, error)
	ValidateChallenge(ctx context.Context, sessionID string, challenge []byte) error
	
	// Session management
	CreateSession(ctx context.Context, session *models.SessionData) error
	GetSession(ctx context.Context, sessionID string) (*models.SessionData, error)
	InvalidateSession(ctx context.Context, sessionID string) error
	
	// Session cleanup
	CleanupExpiredSessions(ctx context.Context) error
}

// WebAuthnConfig represents configuration for WebAuthn operations
type WebAuthnConfig struct {
	// Relying Party configuration
	RPID          string `yaml:"rp_id" validate:"required"`
	RPName        string `yaml:"rp_name" validate:"required"`
	RPIcon        string `yaml:"rp_icon,omitempty"`
	
	// Challenge configuration
	ChallengeLength int           `yaml:"challenge_length" default:"32"`
	ChallengeExpiry time.Duration `yaml:"challenge_expiry" default:"5m"`
	
	// Session configuration
	SessionTimeout  time.Duration `yaml:"session_timeout" default:"15m"`
	MaxSessions     int           `yaml:"max_sessions" default:"5"`
	
	// Security configuration
	RequireUserVerification bool     `yaml:"require_user_verification" default:"false"`
	AllowedOrigins         []string `yaml:"allowed_origins" validate:"required"`
	
	// Credential configuration
	CredentialTimeout     time.Duration `yaml:"credential_timeout" default:"60s"`
	MaxCredentialsPerUser int           `yaml:"max_credentials_per_user" default:"10"`
	
	// Advanced security settings
	RequireResidentKey     bool          `yaml:"require_resident_key" default:"false"`
	UserVerification       string        `yaml:"user_verification" default:"preferred"`
	AttestationPreference  string        `yaml:"attestation_preference" default:"none"`
	SignCountValidation    bool          `yaml:"sign_count_validation" default:"true"`
	CloneDetection         bool          `yaml:"clone_detection" default:"true"`
}

// Validate validates the WebAuthn configuration
func (c *WebAuthnConfig) Validate() error {
	if c.RPID == "" {
		return ErrInvalidConfig("RPID is required")
	}
	if c.RPName == "" {
		return ErrInvalidConfig("RPName is required")
	}
	if len(c.AllowedOrigins) == 0 {
		return ErrInvalidConfig("At least one allowed origin is required")
	}
	if c.ChallengeLength < 16 {
		return ErrInvalidConfig("Challenge length must be at least 16 bytes")
	}
	if c.ChallengeExpiry < time.Minute {
		return ErrInvalidConfig("Challenge expiry must be at least 1 minute")
	}
	return nil
}

// Request/Response types for service operations

// RegistrationStartRequest represents a request to start WebAuthn registration
type RegistrationStartRequest struct {
	UserID       string                     `json:"user_id" validate:"required,uuid4"`
	Username     string                     `json:"username" validate:"required,min=1,max=64"`
	DisplayName  string                     `json:"display_name,omitempty"`
	
	// Registration options
	Options      *RegistrationOptions       `json:"options,omitempty"`
}

// RegistrationOptions represents optional parameters for registration
type RegistrationOptions struct {
	Timeout                         *int                                 `json:"timeout,omitempty"`
	ResidentKeyRequirement          models.ResidentKeyRequirement       `json:"resident_key,omitempty"`
	UserVerification                models.UserVerificationRequirement  `json:"user_verification,omitempty"`
	AttestationConveyancePreference models.AttestationConveyancePreference `json:"attestation,omitempty"`
	AuthenticatorAttachment         models.AuthenticatorAttachment      `json:"authenticator_attachment,omitempty"`
	ExcludeCredentials              [][]byte                             `json:"exclude_credentials,omitempty"`
}

// RegistrationStartResponse represents the response to a registration start request
type RegistrationStartResponse struct {
	SessionID         string                                         `json:"session_id"`
	CreationOptions   *models.PublicKeyCredentialCreationOptions    `json:"options"`
	ExpiresAt         time.Time                                      `json:"expires_at"`
}

// RegistrationFinishRequest represents a request to finish WebAuthn registration
type RegistrationFinishRequest struct {
	SessionID         string                                    `json:"session_id" validate:"required"`
	AttestationResponse *models.AuthenticatorAttestationResponse `json:"response" validate:"required"`
	ClientExtensions  map[string]interface{}                    `json:"client_extensions,omitempty"`
}

// RegistrationResult represents the result of a registration ceremony
type RegistrationResult struct {
	Success       bool                     `json:"success"`
	CredentialID  string                  `json:"credential_id,omitempty"`
	Credential    *models.WebAuthnCredential `json:"credential,omitempty"`
	Warnings      []string                `json:"warnings,omitempty"`
	Error         *ServiceError           `json:"error,omitempty"`
}

// AuthenticationStartRequest represents a request to start WebAuthn authentication
type AuthenticationStartRequest struct {
	UserID            string                     `json:"user_id,omitempty" validate:"required_without=UserIdentifier"`
	UserIdentifier    string                     `json:"user_identifier,omitempty" validate:"required_without=UserID"`
	
	// Authentication options
	Options           *AuthenticationOptions     `json:"options,omitempty"`
	AllowedCredentials [][]byte                  `json:"allowed_credentials,omitempty"`
}

// AuthenticationOptions represents optional parameters for authentication
type AuthenticationOptions struct {
	Timeout                *int                                 `json:"timeout,omitempty"`
	UserVerification       models.UserVerificationRequirement  `json:"user_verification,omitempty"`
	AllowedTransports      []models.AuthenticatorTransport     `json:"allowed_transports,omitempty"`
}

// AuthenticationStartResponse represents the response to an authentication start request
type AuthenticationStartResponse struct {
	SessionID       string                                        `json:"session_id"`
	RequestOptions  *models.PublicKeyCredentialRequestOptions    `json:"options"`
	ExpiresAt       time.Time                                     `json:"expires_at"`
}

// AuthenticationFinishRequest represents a request to finish WebAuthn authentication
type AuthenticationFinishRequest struct {
	SessionID         string                                 `json:"session_id" validate:"required"`
	AssertionResponse *models.AuthenticatorAssertionResponse `json:"response" validate:"required"`
	ClientExtensions  map[string]interface{}                 `json:"client_extensions,omitempty"`
}

// AuthenticationResult represents the result of an authentication ceremony
type AuthenticationResult struct {
	Success         bool                     `json:"success"`
	UserID          string                  `json:"user_id,omitempty"`
	CredentialID    string                  `json:"credential_id,omitempty"`
	SignCount       uint32                  `json:"sign_count,omitempty"`
	AuthenticationTime time.Time            `json:"authentication_time,omitempty"`
	Warnings        []string                `json:"warnings,omitempty"`
	Error           *ServiceError           `json:"error,omitempty"`
}

// CredentialStatistics represents statistics about stored credentials
type CredentialStatistics struct {
	TotalCredentials         int                                           `json:"total_credentials"`
	ActiveCredentials        int                                           `json:"active_credentials"`
	CredentialsByTransport   map[models.AuthenticatorTransport]int        `json:"credentials_by_transport"`
	CredentialsByAttestation map[string]int                                `json:"credentials_by_attestation"`
	AvgCredentialsPerUser    float64                                       `json:"avg_credentials_per_user"`
	UsageStatistics          *CredentialUsageStatistics                   `json:"usage_statistics"`
	CreatedInLast24Hours     int                                          `json:"created_in_last_24_hours"`
	CreatedInLastWeek        int                                          `json:"created_in_last_week"`
	CreatedInLastMonth       int                                          `json:"created_in_last_month"`
}

// CredentialUsageStatistics represents usage statistics for credentials
type CredentialUsageStatistics struct {
	TotalAuthentications     int                  `json:"total_authentications"`
	AuthenticationsLast24h   int                  `json:"authentications_last_24h"`
	AuthenticationsLastWeek  int                  `json:"authentications_last_week"`
	AuthenticationsLastMonth int                  `json:"authentications_last_month"`
	MostActiveCredentials    []CredentialActivity `json:"most_active_credentials"`
	LeastActiveCredentials   []CredentialActivity `json:"least_active_credentials"`
}

// CredentialActivity represents activity information for a credential
type CredentialActivity struct {
	CredentialID     string    `json:"credential_id"`
	UserID           string    `json:"user_id"`
	UsageCount       int       `json:"usage_count"`
	LastUsed         time.Time `json:"last_used"`
	Transport        []models.AuthenticatorTransport `json:"transport"`
}

// ServiceError represents service-level errors
type ServiceError struct {
	Type    ServiceErrorType `json:"type"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details string          `json:"details,omitempty"`
	Cause   error           `json:"cause,omitempty"`
}

// ServiceErrorType represents the type of service error
type ServiceErrorType string

const (
	ErrServiceValidation       ServiceErrorType = "VALIDATION_ERROR"
	ErrServiceAuthentication   ServiceErrorType = "AUTHENTICATION_ERROR"
	ErrServiceAuthorization    ServiceErrorType = "AUTHORIZATION_ERROR"
	ErrServiceNotFound         ServiceErrorType = "NOT_FOUND"
	ErrServiceConflict         ServiceErrorType = "CONFLICT"
	ErrServiceRateLimit        ServiceErrorType = "RATE_LIMIT"
	ErrServiceTimeout          ServiceErrorType = "TIMEOUT"
	ErrServiceInternal         ServiceErrorType = "INTERNAL_ERROR"
	ErrServiceConfiguration    ServiceErrorType = "CONFIGURATION_ERROR"
	ErrServiceDependency       ServiceErrorType = "DEPENDENCY_ERROR"
)

// Error implements the error interface
func (e *ServiceError) Error() string {
	msg := e.Message
	if e.Details != "" {
		msg += ": " + e.Details
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// HTTPStatusCode returns the appropriate HTTP status code for the error
func (e *ServiceError) HTTPStatusCode() int {
	switch e.Type {
	case ErrServiceValidation:
		return 400
	case ErrServiceAuthentication:
		return 401
	case ErrServiceAuthorization:
		return 403
	case ErrServiceNotFound:
		return 404
	case ErrServiceConflict:
		return 409
	case ErrServiceTimeout:
		return 408
	case ErrServiceRateLimit:
		return 429
	case ErrServiceConfiguration, ErrServiceDependency, ErrServiceInternal:
		return 500
	default:
		return 500
	}
}

// NewServiceError creates a new service error
func NewServiceError(errorType ServiceErrorType, message string, details string) *ServiceError {
	return &ServiceError{
		Type:    errorType,
		Code:    string(errorType),
		Message: message,
		Details: details,
	}
}

// NewServiceErrorWithCause creates a new service error with a cause
func NewServiceErrorWithCause(errorType ServiceErrorType, message string, details string, cause error) *ServiceError {
	return &ServiceError{
		Type:    errorType,
		Code:    string(errorType),
		Message: message,
		Details: details,
		Cause:   cause,
	}
}

// Helper functions for error creation

// ErrInvalidConfig creates a configuration error
func ErrInvalidConfig(message string) *ServiceError {
	return NewServiceError(ErrServiceConfiguration, "Invalid configuration", message)
}

// ErrInvalidRequest creates a validation error
func ErrInvalidRequest(message string) *ServiceError {
	return NewServiceError(ErrServiceValidation, "Invalid request", message)
}

// ErrCredentialNotFound creates a not found error for credentials
func ErrCredentialNotFound(credentialID string) *ServiceError {
	return NewServiceError(ErrServiceNotFound, "Credential not found", "Credential ID: "+credentialID)
}

// ErrSessionNotFound creates a not found error for sessions
func ErrSessionNotFound(sessionID string) *ServiceError {
	return NewServiceError(ErrServiceNotFound, "Session not found", "Session ID: "+sessionID)
}

// ErrSessionExpired creates an authentication error for expired sessions
func ErrSessionExpired(sessionID string) *ServiceError {
	return NewServiceError(ErrServiceAuthentication, "Session expired", "Session ID: "+sessionID)
}

// ErrInvalidSignature creates an authentication error for invalid signatures
func ErrInvalidSignature() *ServiceError {
	return NewServiceError(ErrServiceAuthentication, "Invalid signature", "Signature verification failed")
}

// ErrInvalidOrigin creates an authentication error for invalid origins
func ErrInvalidOrigin(origin string) *ServiceError {
	return NewServiceError(ErrServiceAuthentication, "Invalid origin", "Origin: "+origin)
}

// ErrChallengeValidation creates an authentication error for challenge validation
func ErrChallengeValidation() *ServiceError {
	return NewServiceError(ErrServiceAuthentication, "Challenge validation failed", "Invalid challenge data")
}

// ErrCredentialLimit creates a conflict error for credential limits
func ErrCredentialLimit(userID string, limit int) *ServiceError {
	return NewServiceError(ErrServiceConflict, "Credential limit exceeded", 
		fmt.Sprintf("User %s has reached the maximum of %d credentials", userID, limit))
}

// ErrInvalidCredentialData creates a validation error for invalid credential data
func ErrInvalidCredentialData(message string) *ServiceError {
	return NewServiceError(ErrServiceValidation, "Invalid credential data", message)
}

