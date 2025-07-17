package models

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuthenticatorTransport represents the transport mechanism for an authenticator
type AuthenticatorTransport string

const (
	TransportUSB      AuthenticatorTransport = "usb"
	TransportNFC      AuthenticatorTransport = "nfc"
	TransportBLE      AuthenticatorTransport = "ble"
	TransportInternal AuthenticatorTransport = "internal"
	TransportHybrid   AuthenticatorTransport = "hybrid"
)

// IsValid checks if the transport is valid
func (t AuthenticatorTransport) IsValid() bool {
	switch t {
	case TransportUSB, TransportNFC, TransportBLE, TransportInternal, TransportHybrid:
		return true
	default:
		return false
	}
}

// UserVerificationRequirement represents the user verification requirement
type UserVerificationRequirement string

const (
	UserVerificationRequired    UserVerificationRequirement = "required"
	UserVerificationPreferred   UserVerificationRequirement = "preferred"
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// IsValid checks if the user verification requirement is valid
func (u UserVerificationRequirement) IsValid() bool {
	switch u {
	case UserVerificationRequired, UserVerificationPreferred, UserVerificationDiscouraged:
		return true
	default:
		return false
	}
}

// AuthenticatorFlags represents the flags returned by the authenticator
type AuthenticatorFlags struct {
	UserPresent    bool `json:"user_present" db:"user_present"`
	UserVerified   bool `json:"user_verified" db:"user_verified"`
	BackupEligible bool `json:"backup_eligible" db:"backup_eligible"`
	BackupState    bool `json:"backup_state" db:"backup_state"`
}

// Validate validates the AuthenticatorFlags
func (f *AuthenticatorFlags) Validate() error {
	// AuthenticatorFlags are boolean values, so they're always valid
	return nil
}

// WebAuthnCredential represents a WebAuthn credential stored in the database
type WebAuthnCredential struct {
	ID              string                   `json:"id" db:"id" validate:"required"`
	UserID          string                   `json:"user_id" db:"user_id" validate:"required,uuid4"`
	CredentialID    []byte                   `json:"credential_id" db:"credential_id" validate:"required"`
	PublicKey       []byte                   `json:"public_key" db:"public_key" validate:"required"`
	AttestationType string                   `json:"attestation_type" db:"attestation_type"`
	Transport       []AuthenticatorTransport `json:"transport" db:"transport"`
	Flags           AuthenticatorFlags       `json:"flags" db:"flags"`
	SignCount       uint32                   `json:"sign_count" db:"sign_count"`
	CloneWarning    bool                     `json:"clone_warning" db:"clone_warning"`
	Name            string                   `json:"name" db:"name"`
	CreatedAt       time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at" db:"updated_at"`
	LastUsedAt      *time.Time               `json:"last_used_at,omitempty" db:"last_used_at"`
}

// Validate validates the WebAuthnCredential
func (c *WebAuthnCredential) Validate() error {
	if c.ID == "" {
		return errors.New("ID is required")
	}

	if c.UserID == "" {
		return errors.New("UserID is required")
	}

	// Validate UUID format
	if _, err := uuid.Parse(c.UserID); err != nil {
		return errors.New("UserID must be a valid UUID")
	}

	if len(c.CredentialID) == 0 {
		return errors.New("CredentialID is required")
	}

	if len(c.PublicKey) == 0 {
		return errors.New("PublicKey is required")
	}

	// Validate transport methods
	for _, transport := range c.Transport {
		if !transport.IsValid() {
			return fmt.Errorf("invalid transport method: %s", transport)
		}
	}

	// Validate flags
	if err := c.Flags.Validate(); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}

	return nil
}

// SessionData represents temporary session data for WebAuthn ceremonies
type SessionData struct {
	ID                   string                      `json:"id" db:"id" validate:"required"`
	Challenge            []byte                      `json:"challenge" db:"challenge" validate:"required"`
	UserID               string                      `json:"user_id" db:"user_id" validate:"required,uuid4"`
	AllowedCredentialIDs [][]byte                    `json:"allowed_credential_ids" db:"allowed_credential_ids"`
	ExpiresAt            time.Time                   `json:"expires_at" db:"expires_at"`
	CreatedAt            time.Time                   `json:"created_at" db:"created_at"`
	UserVerification     UserVerificationRequirement `json:"user_verification" db:"user_verification"`

	// Deprecated: Use ExpiresAt instead
	Expires time.Time `json:"expires,omitempty" db:"-"`
}

// Validate validates the SessionData
func (s *SessionData) Validate() error {
	if s.ID == "" {
		return errors.New("ID is required")
	}

	if len(s.Challenge) == 0 {
		return errors.New("Challenge is required")
	}

	if len(s.Challenge) < 32 {
		return errors.New("Challenge must be at least 32 bytes")
	}

	// For passwordless authentication, UserID can be empty
	if s.UserID != "" {
		// Validate UUID format only if UserID is provided
		if _, err := uuid.Parse(s.UserID); err != nil {
			return errors.New("UserID must be a valid UUID")
		}
	}

	// Use ExpiresAt, but fallback to Expires for backwards compatibility
	expiryTime := s.ExpiresAt
	if expiryTime.IsZero() && !s.Expires.IsZero() {
		expiryTime = s.Expires
	}

	if expiryTime.Before(time.Now()) {
		return errors.New("Session has expired")
	}

	if s.UserVerification != "" && !s.UserVerification.IsValid() {
		return fmt.Errorf("invalid user verification requirement: %s", s.UserVerification)
	}

	return nil
}

// IsExpired checks if the session has expired
func (s *SessionData) IsExpired() bool {
	// Use ExpiresAt, but fallback to Expires for backwards compatibility
	expiryTime := s.ExpiresAt
	if expiryTime.IsZero() && !s.Expires.IsZero() {
		expiryTime = s.Expires
	}
	return expiryTime.Before(time.Now())
}

// WebAuthnErrorType represents the type of WebAuthn error
type WebAuthnErrorType string

const (
	ErrRegistrationFailed   WebAuthnErrorType = "REGISTRATION_FAILED"
	ErrAuthenticationFailed WebAuthnErrorType = "AUTHENTICATION_FAILED"
	ErrCredentialNotFound   WebAuthnErrorType = "CREDENTIAL_NOT_FOUND"
	ErrInvalidChallenge     WebAuthnErrorType = "INVALID_CHALLENGE"
	ErrInvalidOrigin        WebAuthnErrorType = "INVALID_ORIGIN"
	ErrInvalidSignature     WebAuthnErrorType = "INVALID_SIGNATURE"
	ErrSessionExpired       WebAuthnErrorType = "SESSION_EXPIRED"
	ErrValidationFailed     WebAuthnErrorType = "VALIDATION_FAILED"
	ErrInternalError        WebAuthnErrorType = "INTERNAL_ERROR"
	ErrRateLimited          WebAuthnErrorType = "RATE_LIMITED"
	ErrTimeout              WebAuthnErrorType = "TIMEOUT"

	// Legacy error types for backwards compatibility
	ErrorTypeValidation     = "validation"
	ErrorTypeAuthentication = "authentication"
	ErrorTypeNotFound       = "not_found"
	ErrorTypeInternal       = "internal"
	ErrorTypeTimeout        = "timeout"
	ErrorTypeRateLimited    = "rate_limited"
)

// WebAuthnError represents a custom error for WebAuthn operations
type WebAuthnError struct {
	Type    WebAuthnErrorType `json:"type"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details string            `json:"details,omitempty"`
	Cause   error             `json:"cause,omitempty"`
}

// Error implements the error interface
func (e *WebAuthnError) Error() string {
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
func (e *WebAuthnError) HTTPStatusCode() int {
	switch e.Type {
	case ErrValidationFailed:
		return 400
	case ErrAuthenticationFailed, ErrInvalidSignature, ErrInvalidChallenge:
		return 401
	case ErrCredentialNotFound:
		return 404
	case ErrTimeout:
		return 408
	case ErrRateLimited:
		return 429
	case ErrInternalError:
		return 500
	default:
		// Handle legacy error types for backwards compatibility
		switch string(e.Type) {
		case ErrorTypeValidation:
			return 400
		case ErrorTypeAuthentication:
			return 401
		case ErrorTypeNotFound:
			return 404
		case ErrorTypeTimeout:
			return 408
		case ErrorTypeRateLimited:
			return 429
		case ErrorTypeInternal:
			return 500
		default:
			return 500
		}
	}
}

// NewWebAuthnError creates a new WebAuthnError
func NewWebAuthnError(errorType WebAuthnErrorType, message string, details string) *WebAuthnError {
	return &WebAuthnError{
		Type:    errorType,
		Code:    string(errorType),
		Message: message,
		Details: details,
	}
}

// NewWebAuthnErrorWithCause creates a new WebAuthnError with a cause
func NewWebAuthnErrorWithCause(errorType WebAuthnErrorType, message string, details string, cause error) *WebAuthnError {
	return &WebAuthnError{
		Type:    errorType,
		Code:    string(errorType),
		Message: message,
		Details: details,
		Cause:   cause,
	}
}

// IsWebAuthnError checks if an error is a WebAuthnError
func IsWebAuthnError(err error) bool {
	_, ok := err.(*WebAuthnError)
	return ok
}

// GetWebAuthnError extracts WebAuthnError from an error
func GetWebAuthnError(err error) *WebAuthnError {
	if webAuthnErr, ok := err.(*WebAuthnError); ok {
		return webAuthnErr
	}
	return nil
}

// Legacy function for backwards compatibility with ErrorType
func NewWebAuthnErrorLegacy(errorType string, message string, cause error) *WebAuthnError {
	return &WebAuthnError{
		Type:    WebAuthnErrorType(errorType),
		Code:    errorType,
		Message: message,
		Cause:   cause,
	}
}

// CredentialDescriptor represents a credential descriptor for WebAuthn
type CredentialDescriptor struct {
	Type       string                   `json:"type"`
	ID         []byte                   `json:"id"`
	Transports []AuthenticatorTransport `json:"transports,omitempty"`
}

// AttestationConveyancePreference represents the attestation conveyance preference
type AttestationConveyancePreference string

const (
	AttestationConveyanceNone     AttestationConveyancePreference = "none"
	AttestationConveyanceIndirect AttestationConveyancePreference = "indirect"
	AttestationConveyanceDirect   AttestationConveyancePreference = "direct"
)

// IsValid checks if the attestation conveyance preference is valid
func (a AttestationConveyancePreference) IsValid() bool {
	switch a {
	case AttestationConveyanceNone, AttestationConveyanceIndirect, AttestationConveyanceDirect:
		return true
	default:
		return false
	}
}

// ResidentKeyRequirement represents the resident key requirement
type ResidentKeyRequirement string

const (
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
	ResidentKeyPreferred   ResidentKeyRequirement = "preferred"
	ResidentKeyRequired    ResidentKeyRequirement = "required"
)

// IsValid checks if the resident key requirement is valid
func (r ResidentKeyRequirement) IsValid() bool {
	switch r {
	case ResidentKeyDiscouraged, ResidentKeyPreferred, ResidentKeyRequired:
		return true
	default:
		return false
	}
}

// AuthenticatorAttachment represents the authenticator attachment modality
type AuthenticatorAttachment string

const (
	AuthenticatorAttachmentPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorAttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// IsValid checks if the authenticator attachment is valid
func (a AuthenticatorAttachment) IsValid() bool {
	switch a {
	case AuthenticatorAttachmentPlatform, AuthenticatorAttachmentCrossPlatform:
		return true
	default:
		return false
	}
}

// COSEAlgorithmIdentifier represents a COSE algorithm identifier
type COSEAlgorithmIdentifier int

const (
	COSEAlgES256 COSEAlgorithmIdentifier = -7   // ECDSA w/ SHA-256
	COSEAlgES384 COSEAlgorithmIdentifier = -35  // ECDSA w/ SHA-384
	COSEAlgES512 COSEAlgorithmIdentifier = -36  // ECDSA w/ SHA-512
	COSEAlgRS256 COSEAlgorithmIdentifier = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
	COSEAlgRS384 COSEAlgorithmIdentifier = -258 // RSASSA-PKCS1-v1_5 w/ SHA-384
	COSEAlgRS512 COSEAlgorithmIdentifier = -259 // RSASSA-PKCS1-v1_5 w/ SHA-512
	COSEAlgPS256 COSEAlgorithmIdentifier = -37  // RSASSA-PSS w/ SHA-256
	COSEAlgPS384 COSEAlgorithmIdentifier = -38  // RSASSA-PSS w/ SHA-384
	COSEAlgPS512 COSEAlgorithmIdentifier = -39  // RSASSA-PSS w/ SHA-512
	COSEAlgEdDSA COSEAlgorithmIdentifier = -8   // EdDSA
)

// IsValid checks if the COSE algorithm identifier is valid
func (c COSEAlgorithmIdentifier) IsValid() bool {
	switch c {
	case COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgRS256, COSEAlgRS384, COSEAlgRS512, COSEAlgPS256, COSEAlgPS384, COSEAlgPS512, COSEAlgEdDSA:
		return true
	default:
		return false
	}
}

// String returns the string representation of the COSE algorithm identifier
func (c COSEAlgorithmIdentifier) String() string {
	switch c {
	case COSEAlgES256:
		return "ES256"
	case COSEAlgES384:
		return "ES384"
	case COSEAlgES512:
		return "ES512"
	case COSEAlgRS256:
		return "RS256"
	case COSEAlgRS384:
		return "RS384"
	case COSEAlgRS512:
		return "RS512"
	case COSEAlgPS256:
		return "PS256"
	case COSEAlgPS384:
		return "PS384"
	case COSEAlgPS512:
		return "PS512"
	case COSEAlgEdDSA:
		return "EdDSA"
	default:
		return fmt.Sprintf("Unknown(%d)", int(c))
	}
}

// PublicKeyCredentialParameters represents the public key credential parameters
type PublicKeyCredentialParameters struct {
	Type string                  `json:"type"`
	Alg  COSEAlgorithmIdentifier `json:"alg"`
}

// ValidateCredentialParameters validates a slice of credential parameters
func ValidateCredentialParameters(params []PublicKeyCredentialParameters) error {
	if len(params) == 0 {
		return errors.New("at least one credential parameter is required")
	}

	for i, param := range params {
		if param.Type == "" {
			return fmt.Errorf("credential parameter %d: type is required", i)
		}
		if param.Type != "public-key" {
			return fmt.Errorf("credential parameter %d: unsupported type '%s'", i, param.Type)
		}
		if !param.Alg.IsValid() {
			return fmt.Errorf("credential parameter %d: unsupported algorithm %d", i, param.Alg)
		}
	}

	return nil
}

// DefaultCredentialParameters returns the default credential parameters
func DefaultCredentialParameters() []PublicKeyCredentialParameters {
	return []PublicKeyCredentialParameters{
		{Type: "public-key", Alg: COSEAlgES256},
		{Type: "public-key", Alg: COSEAlgRS256},
		{Type: "public-key", Alg: COSEAlgPS256},
		{Type: "public-key", Alg: COSEAlgEdDSA},
	}
}

// DatabaseMappingHelpers provides helper methods for database operations

// TransportsToString converts a slice of AuthenticatorTransport to a comma-separated string
func TransportsToString(transports []AuthenticatorTransport) string {
	if len(transports) == 0 {
		return ""
	}

	stringTransports := make([]string, len(transports))
	for i, transport := range transports {
		stringTransports[i] = string(transport)
	}

	return strings.Join(stringTransports, ",")
}

// StringToTransports converts a comma-separated string to a slice of AuthenticatorTransport
func StringToTransports(s string) []AuthenticatorTransport {
	if s == "" {
		return []AuthenticatorTransport{}
	}

	parts := strings.Split(s, ",")
	transports := make([]AuthenticatorTransport, 0, len(parts))

	for _, part := range parts {
		transport := AuthenticatorTransport(strings.TrimSpace(part))
		if transport.IsValid() {
			transports = append(transports, transport)
		}
	}

	return transports
}

// Request/Response Models for WebAuthn API Endpoints

// RegistrationStartRequest represents a request to start WebAuthn registration
type RegistrationStartRequest struct {
	UserID   string `json:"user_id" validate:"required,uuid4"`
	Username string `json:"username" validate:"required,min=1,max=64"`

	// Optional registration options
	Options *RegistrationOptions `json:"options,omitempty"`
}

// RegistrationOptions represents optional parameters for registration
type RegistrationOptions struct {
	Timeout                         *int                            `json:"timeout,omitempty"`
	ResidentKeyRequirement          ResidentKeyRequirement          `json:"resident_key,omitempty"`
	UserVerification                UserVerificationRequirement     `json:"user_verification,omitempty"`
	AttestationConveyancePreference AttestationConveyancePreference `json:"attestation,omitempty"`
	AuthenticatorAttachment         AuthenticatorAttachment         `json:"authenticator_attachment,omitempty"`
}

// RegistrationStartResponse represents the response to a registration start request
type RegistrationStartResponse struct {
	SessionID string                              `json:"session_id"`
	Options   *PublicKeyCredentialCreationOptions `json:"options"`
}

// PublicKeyCredentialCreationOptions represents the WebAuthn creation options
type PublicKeyCredentialCreationOptions struct {
	Challenge              Base64URLBytes                  `json:"challenge"`
	RP                     *RelyingPartyEntity             `json:"rp"`
	User                   *UserEntity                     `json:"user"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                *int                            `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptor          `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelectionCriteria `json:"authenticatorSelection,omitempty"`
	Attestation            AttestationConveyancePreference `json:"attestation,omitempty"`
}

// RelyingPartyEntity represents the relying party
type RelyingPartyEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity represents a WebAuthn user entity
type UserEntity struct {
	ID          Base64URLBytes `json:"id"`
	Name        string         `json:"name"`
	DisplayName string         `json:"displayName"`
}

// AuthenticatorSelectionCriteria represents authenticator selection criteria
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	ResidentKey             ResidentKeyRequirement      `json:"residentKey,omitempty"`
	RequireResidentKey      bool                        `json:"requireResidentKey,omitempty"`
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}

// RegistrationFinishRequest represents a request to finish WebAuthn registration
type RegistrationFinishRequest struct {
	SessionID string                            `json:"session_id" validate:"required"`
	Response  *AuthenticatorAttestationResponse `json:"response" validate:"required"`
}

// AuthenticatorAttestationResponse represents the authenticator attestation response
type AuthenticatorAttestationResponse struct {
	ID       string                                `json:"id"`
	RawID    []byte                                `json:"rawId"`
	Type     string                                `json:"type"`
	Response *AuthenticatorAttestationResponseData `json:"response"`
}

// AuthenticatorAttestationResponseData represents the response data from attestation
type AuthenticatorAttestationResponseData struct {
	ClientDataJSON    []byte   `json:"clientDataJSON"`
	AttestationObject []byte   `json:"attestationObject"`
	Transports        []string `json:"transports,omitempty"`
}

// RegistrationResult represents the result of a registration ceremony
type RegistrationResult struct {
	Success      bool                `json:"success"`
	CredentialID string              `json:"credential_id,omitempty"`
	Credential   *WebAuthnCredential `json:"credential,omitempty"`
	Error        string              `json:"error,omitempty"`
}

// AuthenticationStartRequest represents a request to start WebAuthn authentication
type AuthenticationStartRequest struct {
	UserID         string `json:"user_id,omitempty"`
	UserIdentifier string `json:"user_identifier,omitempty"`

	// Optional authentication options
	Options            *AuthenticationOptions `json:"options,omitempty"`
	AllowedCredentials [][]byte               `json:"allowed_credentials,omitempty"`
}

// AuthenticationOptions represents optional parameters for authentication
type AuthenticationOptions struct {
	Timeout           *int                        `json:"timeout,omitempty"`
	UserVerification  UserVerificationRequirement `json:"user_verification,omitempty"`
	AllowedTransports []AuthenticatorTransport    `json:"allowed_transports,omitempty"`
}

// AuthenticationStartResponse represents the response to an authentication start request
type AuthenticationStartResponse struct {
	SessionID string                             `json:"session_id"`
	Options   *PublicKeyCredentialRequestOptions `json:"options"`
}

// PublicKeyCredentialRequestOptions represents the WebAuthn request options
type PublicKeyCredentialRequestOptions struct {
	Challenge        Base64URLBytes              `json:"challenge"`
	Timeout          *int                        `json:"timeout,omitempty"`
	RPID             string                      `json:"rpId"`
	AllowCredentials []CredentialDescriptor      `json:"allowCredentials,omitempty"`
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
}

// AuthenticationFinishRequest represents a request to finish WebAuthn authentication
type AuthenticationFinishRequest struct {
	SessionID string                          `json:"session_id" validate:"required"`
	Response  *AuthenticatorAssertionResponse `json:"response" validate:"required"`
}

// AuthenticatorAssertionResponse represents the authenticator assertion response
type AuthenticatorAssertionResponse struct {
	ID       string                              `json:"id"`
	RawID    []byte                              `json:"rawId"`
	Type     string                              `json:"type"`
	Response *AuthenticatorAssertionResponseData `json:"response"`
}

// AuthenticatorAssertionResponseData represents the response data from assertion
type AuthenticatorAssertionResponseData struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle,omitempty"`
}

// AuthenticationResult represents the result of an authentication ceremony
type AuthenticationResult struct {
	Success      bool   `json:"success"`
	UserID       string `json:"user_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Base64URLBytes represents a byte slice that marshals to/from base64url encoding
type Base64URLBytes []byte

// MarshalJSON implements json.Marshaler interface for Base64URLBytes
func (b Base64URLBytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler interface for Base64URLBytes
func (b *Base64URLBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*b = nil
		return nil
	}

	// Try multiple base64 encodings to be flexible
	decodedBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Try with padding
		decodedBytes, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			// Try standard base64
			decodedBytes, err = base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("failed to decode base64 string: %w", err)
			}
		}
	}
	*b = decodedBytes
	return nil
}

// String returns the base64url encoded string representation
func (b Base64URLBytes) String() string {
	return base64.RawURLEncoding.EncodeToString(b)
}
