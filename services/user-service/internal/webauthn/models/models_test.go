package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthnCredential tests the WebAuthnCredential structure
func TestWebAuthnCredential(t *testing.T) {
	tests := []struct {
		name        string
		credential  WebAuthnCredential
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid_Credential",
			credential: WebAuthnCredential{
				ID:           "test-credential-id",
				UserID:       "550e8400-e29b-41d4-a716-446655440000",
				CredentialID: []byte("test-credential-id-bytes"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
				Transport:    []AuthenticatorTransport{TransportUSB, TransportNFC},
				Flags: AuthenticatorFlags{
					UserPresent:    true,
					UserVerified:   true,
					BackupEligible: false,
					BackupState:    false,
				},
				SignCount: 0,
				CloneWarning: false,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			expectError: false,
		},
		{
			name: "Missing_ID",
			credential: WebAuthnCredential{
				UserID:       "550e8400-e29b-41d4-a716-446655440000",
				CredentialID: []byte("test-credential-id-bytes"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
			},
			expectError: true,
			errorMsg:    "ID is required",
		},
		{
			name: "Missing_UserID",
			credential: WebAuthnCredential{
				ID:           "test-credential-id",
				CredentialID: []byte("test-credential-id-bytes"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
			},
			expectError: true,
			errorMsg:    "UserID is required",
		},
		{
			name: "Invalid_UserID_Format",
			credential: WebAuthnCredential{
				ID:           "test-credential-id",
				UserID:       "invalid-uuid",
				CredentialID: []byte("test-credential-id-bytes"),
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
			},
			expectError: true,
			errorMsg:    "UserID must be a valid UUID",
		},
		{
			name: "Missing_CredentialID",
			credential: WebAuthnCredential{
				ID:           "test-credential-id",
				UserID:       "550e8400-e29b-41d4-a716-446655440000",
				PublicKey:    []byte("test-public-key"),
				AttestationType: "none",
			},
			expectError: true,
			errorMsg:    "CredentialID is required",
		},
		{
			name: "Missing_PublicKey",
			credential: WebAuthnCredential{
				ID:           "test-credential-id",
				UserID:       "550e8400-e29b-41d4-a716-446655440000",
				CredentialID: []byte("test-credential-id-bytes"),
				AttestationType: "none",
			},
			expectError: true,
			errorMsg:    "PublicKey is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.credential.Validate()

			if tt.expectError {
				assert.Error(t, err, "Credential validation should fail")
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
			} else {
				assert.NoError(t, err, "Credential validation should pass")
			}
		})
	}
}

// TestWebAuthnCredentialJSONSerialization tests JSON serialization
func TestWebAuthnCredentialJSONSerialization(t *testing.T) {
	credential := WebAuthnCredential{
		ID:           "test-credential-id",
		UserID:       "550e8400-e29b-41d4-a716-446655440000",
		CredentialID: []byte("test-credential-id-bytes"),
		PublicKey:    []byte("test-public-key"),
		AttestationType: "none",
		Transport:    []AuthenticatorTransport{TransportUSB, TransportNFC},
		Flags: AuthenticatorFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: false,
			BackupState:    false,
		},
		SignCount: 42,
		CloneWarning: false,
		CreatedAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(credential)
	require.NoError(t, err, "JSON marshaling should not fail")

	// Test JSON unmarshaling
	var unmarshaled WebAuthnCredential
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "JSON unmarshaling should not fail")

	// Verify data integrity
	assert.Equal(t, credential.ID, unmarshaled.ID)
	assert.Equal(t, credential.UserID, unmarshaled.UserID)
	assert.Equal(t, credential.CredentialID, unmarshaled.CredentialID)
	assert.Equal(t, credential.PublicKey, unmarshaled.PublicKey)
	assert.Equal(t, credential.AttestationType, unmarshaled.AttestationType)
	assert.Equal(t, credential.Transport, unmarshaled.Transport)
	assert.Equal(t, credential.Flags, unmarshaled.Flags)
	assert.Equal(t, credential.SignCount, unmarshaled.SignCount)
	assert.Equal(t, credential.CloneWarning, unmarshaled.CloneWarning)
	assert.True(t, credential.CreatedAt.Equal(unmarshaled.CreatedAt))
	assert.True(t, credential.UpdatedAt.Equal(unmarshaled.UpdatedAt))
}

// TestAuthenticatorFlags tests AuthenticatorFlags structure
func TestAuthenticatorFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags AuthenticatorFlags
		valid bool
	}{
		{
			name: "Valid_Flags_All_True",
			flags: AuthenticatorFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
			valid: true,
		},
		{
			name: "Valid_Flags_All_False",
			flags: AuthenticatorFlags{
				UserPresent:    false,
				UserVerified:   false,
				BackupEligible: false,
				BackupState:    false,
			},
			valid: true,
		},
		{
			name: "Valid_Flags_Mixed",
			flags: AuthenticatorFlags{
				UserPresent:    true,
				UserVerified:   false,
				BackupEligible: true,
				BackupState:    false,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flags.Validate()
			if tt.valid {
				assert.NoError(t, err, "AuthenticatorFlags validation should pass")
			} else {
				assert.Error(t, err, "AuthenticatorFlags validation should fail")
			}
		})
	}
}

// TestAuthenticatorFlagsJSONSerialization tests JSON serialization for AuthenticatorFlags
func TestAuthenticatorFlagsJSONSerialization(t *testing.T) {
	flags := AuthenticatorFlags{
		UserPresent:    true,
		UserVerified:   true,
		BackupEligible: false,
		BackupState:    false,
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(flags)
	require.NoError(t, err, "JSON marshaling should not fail")

	// Test JSON unmarshaling
	var unmarshaled AuthenticatorFlags
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "JSON unmarshaling should not fail")

	// Verify data integrity
	assert.Equal(t, flags.UserPresent, unmarshaled.UserPresent)
	assert.Equal(t, flags.UserVerified, unmarshaled.UserVerified)
	assert.Equal(t, flags.BackupEligible, unmarshaled.BackupEligible)
	assert.Equal(t, flags.BackupState, unmarshaled.BackupState)
}

// TestSessionData tests SessionData structure
func TestSessionData(t *testing.T) {
	tests := []struct {
		name        string
		sessionData SessionData
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid_SessionData",
			sessionData: SessionData{
				Challenge:   []byte("test-challenge-data-12345678901234567890"),
				UserID:      "550e8400-e29b-41d4-a716-446655440000",
				AllowedCredentialIDs: [][]byte{
					[]byte("credential-1"),
					[]byte("credential-2"),
				},
				Expires:      time.Now().Add(5 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: false,
		},
		{
			name: "Missing_Challenge",
			sessionData: SessionData{
				UserID:      "550e8400-e29b-41d4-a716-446655440000",
				Expires:     time.Now().Add(5 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: true,
			errorMsg:    "Challenge is required",
		},
		{
			name: "Challenge_Too_Short",
			sessionData: SessionData{
				Challenge:   []byte("short"),
				UserID:      "550e8400-e29b-41d4-a716-446655440000",
				Expires:     time.Now().Add(5 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: true,
			errorMsg:    "Challenge must be at least 32 bytes",
		},
		{
			name: "Missing_UserID",
			sessionData: SessionData{
				Challenge:   []byte("test-challenge-data-12345678901234567890"),
				Expires:     time.Now().Add(5 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: true,
			errorMsg:    "UserID is required",
		},
		{
			name: "Invalid_UserID_Format",
			sessionData: SessionData{
				Challenge:   []byte("test-challenge-data-12345678901234567890"),
				UserID:      "invalid-uuid",
				Expires:     time.Now().Add(5 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: true,
			errorMsg:    "UserID must be a valid UUID",
		},
		{
			name: "Expired_Session",
			sessionData: SessionData{
				Challenge:   []byte("test-challenge-data-12345678901234567890"),
				UserID:      "550e8400-e29b-41d4-a716-446655440000",
				Expires:     time.Now().Add(-1 * time.Minute),
				UserVerification: UserVerificationRequired,
			},
			expectError: true,
			errorMsg:    "Session has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sessionData.Validate()

			if tt.expectError {
				assert.Error(t, err, "SessionData validation should fail")
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
			} else {
				assert.NoError(t, err, "SessionData validation should pass")
			}
		})
	}
}

// TestSessionDataJSONSerialization tests JSON serialization for SessionData
func TestSessionDataJSONSerialization(t *testing.T) {
	sessionData := SessionData{
		Challenge:   []byte("test-challenge-data-12345678901234567890"),
		UserID:      "550e8400-e29b-41d4-a716-446655440000",
		AllowedCredentialIDs: [][]byte{
			[]byte("credential-1"),
			[]byte("credential-2"),
		},
		Expires:      time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		UserVerification: UserVerificationRequired,
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(sessionData)
	require.NoError(t, err, "JSON marshaling should not fail")

	// Test JSON unmarshaling
	var unmarshaled SessionData
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err, "JSON unmarshaling should not fail")

	// Verify data integrity
	assert.Equal(t, sessionData.Challenge, unmarshaled.Challenge)
	assert.Equal(t, sessionData.UserID, unmarshaled.UserID)
	assert.Equal(t, sessionData.AllowedCredentialIDs, unmarshaled.AllowedCredentialIDs)
	assert.True(t, sessionData.Expires.Equal(unmarshaled.Expires))
	assert.Equal(t, sessionData.UserVerification, unmarshaled.UserVerification)
}

// TestWebAuthnError tests custom error types
func TestWebAuthnError(t *testing.T) {
	tests := []struct {
		name         string
		errorType    ErrorType
		message      string
		cause        error
		expectedCode int
	}{
		{
			name:         "ValidationError",
			errorType:    ErrorTypeValidation,
			message:      "Invalid credential data",
			cause:        nil,
			expectedCode: 400,
		},
		{
			name:         "AuthenticationError",
			errorType:    ErrorTypeAuthentication,
			message:      "Authentication failed",
			cause:        nil,
			expectedCode: 401,
		},
		{
			name:         "NotFoundError",
			errorType:    ErrorTypeNotFound,
			message:      "Credential not found",
			cause:        nil,
			expectedCode: 404,
		},
		{
			name:         "InternalError",
			errorType:    ErrorTypeInternal,
			message:      "Database connection failed",
			cause:        assert.AnError,
			expectedCode: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewWebAuthnError(tt.errorType, tt.message, tt.cause)

			assert.Equal(t, tt.errorType, err.Type)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.cause, err.Cause)
			assert.Equal(t, tt.expectedCode, err.HTTPStatusCode())

			// Test error message formatting
			expectedErrorMsg := tt.message
			if tt.cause != nil {
				expectedErrorMsg += ": " + tt.cause.Error()
			}
			assert.Equal(t, expectedErrorMsg, err.Error())
		})
	}
}

// TestAuthenticatorTransport tests AuthenticatorTransport enumeration
func TestAuthenticatorTransport(t *testing.T) {
	tests := []struct {
		name      string
		transport AuthenticatorTransport
		valid     bool
	}{
		{"USB", TransportUSB, true},
		{"NFC", TransportNFC, true},
		{"BLE", TransportBLE, true},
		{"Internal", TransportInternal, true},
		{"Invalid", AuthenticatorTransport("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.transport.IsValid()
			assert.Equal(t, tt.valid, valid, "Transport validation should match expected")
		})
	}
}

// TestUserVerificationRequirement tests UserVerificationRequirement enumeration
func TestUserVerificationRequirement(t *testing.T) {
	tests := []struct {
		name         string
		requirement  UserVerificationRequirement
		valid        bool
	}{
		{"Required", UserVerificationRequired, true},
		{"Preferred", UserVerificationPreferred, true},
		{"Discouraged", UserVerificationDiscouraged, true},
		{"Invalid", UserVerificationRequirement("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.requirement.IsValid()
			assert.Equal(t, tt.valid, valid, "UserVerification requirement validation should match expected")
		})
	}
}