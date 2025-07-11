package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestTransportsToString tests the TransportsToString helper function
func TestTransportsToString(t *testing.T) {
	tests := []struct {
		name       string
		transports []AuthenticatorTransport
		expected   string
	}{
		{
			name:       "Empty_Transports",
			transports: []AuthenticatorTransport{},
			expected:   "",
		},
		{
			name:       "Single_Transport",
			transports: []AuthenticatorTransport{TransportUSB},
			expected:   "usb",
		},
		{
			name:       "Multiple_Transports",
			transports: []AuthenticatorTransport{TransportUSB, TransportNFC, TransportBLE},
			expected:   "usb,nfc,ble",
		},
		{
			name:       "All_Transports",
			transports: []AuthenticatorTransport{TransportUSB, TransportNFC, TransportBLE, TransportInternal},
			expected:   "usb,nfc,ble,internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TransportsToString(tt.transports)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestStringToTransports tests the StringToTransports helper function
func TestStringToTransports(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []AuthenticatorTransport
	}{
		{
			name:     "Empty_String",
			input:    "",
			expected: []AuthenticatorTransport{},
		},
		{
			name:     "Single_Transport",
			input:    "usb",
			expected: []AuthenticatorTransport{TransportUSB},
		},
		{
			name:     "Multiple_Transports",
			input:    "usb,nfc,ble",
			expected: []AuthenticatorTransport{TransportUSB, TransportNFC, TransportBLE},
		},
		{
			name:     "Transports_With_Spaces",
			input:    "usb, nfc, ble",
			expected: []AuthenticatorTransport{TransportUSB, TransportNFC, TransportBLE},
		},
		{
			name:     "Invalid_Transport_Filtered",
			input:    "usb,invalid,nfc",
			expected: []AuthenticatorTransport{TransportUSB, TransportNFC},
		},
		{
			name:     "All_Invalid_Transports",
			input:    "invalid1,invalid2",
			expected: []AuthenticatorTransport{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringToTransports(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestTransportsRoundTrip tests the round-trip conversion
func TestTransportsRoundTrip(t *testing.T) {
	originalTransports := []AuthenticatorTransport{
		TransportUSB,
		TransportNFC,
		TransportBLE,
		TransportInternal,
	}

	// Convert to string
	str := TransportsToString(originalTransports)
	
	// Convert back to transports
	convertedTransports := StringToTransports(str)
	
	// Should be identical
	assert.Equal(t, originalTransports, convertedTransports)
}

// TestValidateCredentialParameters tests the ValidateCredentialParameters function
func TestValidateCredentialParameters(t *testing.T) {
	tests := []struct {
		name        string
		params      []PublicKeyCredentialParameters
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty_Parameters",
			params:      []PublicKeyCredentialParameters{},
			expectError: true,
			errorMsg:    "at least one credential parameter is required",
		},
		{
			name: "Valid_Single_Parameter",
			params: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: COSEAlgES256},
			},
			expectError: false,
		},
		{
			name: "Valid_Multiple_Parameters",
			params: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: COSEAlgES256},
				{Type: "public-key", Alg: COSEAlgRS256},
				{Type: "public-key", Alg: COSEAlgPS256},
			},
			expectError: false,
		},
		{
			name: "Missing_Type",
			params: []PublicKeyCredentialParameters{
				{Type: "", Alg: COSEAlgES256},
			},
			expectError: true,
			errorMsg:    "credential parameter 0: type is required",
		},
		{
			name: "Invalid_Type",
			params: []PublicKeyCredentialParameters{
				{Type: "invalid-type", Alg: COSEAlgES256},
			},
			expectError: true,
			errorMsg:    "credential parameter 0: unsupported type 'invalid-type'",
		},
		{
			name: "Invalid_Algorithm",
			params: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: COSEAlgorithmIdentifier(999)},
			},
			expectError: true,
			errorMsg:    "credential parameter 0: unsupported algorithm 999",
		},
		{
			name: "Mixed_Valid_Invalid",
			params: []PublicKeyCredentialParameters{
				{Type: "public-key", Alg: COSEAlgES256},
				{Type: "invalid-type", Alg: COSEAlgRS256},
			},
			expectError: true,
			errorMsg:    "credential parameter 1: unsupported type 'invalid-type'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialParameters(tt.params)

			if tt.expectError {
				assert.Error(t, err, "ValidateCredentialParameters should fail")
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
			} else {
				assert.NoError(t, err, "ValidateCredentialParameters should pass")
			}
		})
	}
}

// TestDefaultCredentialParameters tests the DefaultCredentialParameters function
func TestDefaultCredentialParameters(t *testing.T) {
	params := DefaultCredentialParameters()
	
	// Should not be empty
	assert.NotEmpty(t, params, "Default parameters should not be empty")
	
	// Should contain expected algorithms
	expectedAlgs := []COSEAlgorithmIdentifier{
		COSEAlgES256,
		COSEAlgRS256,
		COSEAlgPS256,
		COSEAlgEdDSA,
	}
	
	assert.Equal(t, len(expectedAlgs), len(params), "Should have expected number of parameters")
	
	for i, param := range params {
		assert.Equal(t, "public-key", param.Type, "All parameters should have public-key type")
		assert.Equal(t, expectedAlgs[i], param.Alg, "Algorithm should match expected")
	}
	
	// Should be valid
	err := ValidateCredentialParameters(params)
	assert.NoError(t, err, "Default parameters should be valid")
}

// TestCOSEAlgorithmIdentifierString tests the String method of COSEAlgorithmIdentifier
func TestCOSEAlgorithmIdentifierString(t *testing.T) {
	tests := []struct {
		name     string
		alg      COSEAlgorithmIdentifier
		expected string
	}{
		{"ES256", COSEAlgES256, "ES256"},
		{"ES384", COSEAlgES384, "ES384"},
		{"ES512", COSEAlgES512, "ES512"},
		{"RS256", COSEAlgRS256, "RS256"},
		{"RS384", COSEAlgRS384, "RS384"},
		{"RS512", COSEAlgRS512, "RS512"},
		{"PS256", COSEAlgPS256, "PS256"},
		{"PS384", COSEAlgPS384, "PS384"},
		{"PS512", COSEAlgPS512, "PS512"},
		{"EdDSA", COSEAlgEdDSA, "EdDSA"},
		{"Unknown", COSEAlgorithmIdentifier(999), "Unknown(999)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alg.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCOSEAlgorithmIdentifierIsValid tests the IsValid method of COSEAlgorithmIdentifier
func TestCOSEAlgorithmIdentifierIsValid(t *testing.T) {
	tests := []struct {
		name     string
		alg      COSEAlgorithmIdentifier
		expected bool
	}{
		{"ES256", COSEAlgES256, true},
		{"ES384", COSEAlgES384, true},
		{"ES512", COSEAlgES512, true},
		{"RS256", COSEAlgRS256, true},
		{"RS384", COSEAlgRS384, true},
		{"RS512", COSEAlgRS512, true},
		{"PS256", COSEAlgPS256, true},
		{"PS384", COSEAlgPS384, true},
		{"PS512", COSEAlgPS512, true},
		{"EdDSA", COSEAlgEdDSA, true},
		{"Invalid", COSEAlgorithmIdentifier(999), false},
		{"Invalid_Negative", COSEAlgorithmIdentifier(-999), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.alg.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAttestationConveyancePreferenceIsValid tests the IsValid method of AttestationConveyancePreference
func TestAttestationConveyancePreferenceIsValid(t *testing.T) {
	tests := []struct {
		name     string
		pref     AttestationConveyancePreference
		expected bool
	}{
		{"None", AttestationConveyanceNone, true},
		{"Indirect", AttestationConveyanceIndirect, true},
		{"Direct", AttestationConveyanceDirect, true},
		{"Invalid", AttestationConveyancePreference("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pref.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResidentKeyRequirementIsValid tests the IsValid method of ResidentKeyRequirement
func TestResidentKeyRequirementIsValid(t *testing.T) {
	tests := []struct {
		name     string
		req      ResidentKeyRequirement
		expected bool
	}{
		{"Discouraged", ResidentKeyDiscouraged, true},
		{"Preferred", ResidentKeyPreferred, true},
		{"Required", ResidentKeyRequired, true},
		{"Invalid", ResidentKeyRequirement("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.req.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthenticatorAttachmentIsValid tests the IsValid method of AuthenticatorAttachment
func TestAuthenticatorAttachmentIsValid(t *testing.T) {
	tests := []struct {
		name     string
		attach   AuthenticatorAttachment
		expected bool
	}{
		{"Platform", AuthenticatorAttachmentPlatform, true},
		{"CrossPlatform", AuthenticatorAttachmentCrossPlatform, true},
		{"Invalid", AuthenticatorAttachment("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attach.IsValid()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsWebAuthnError tests the IsWebAuthnError function
func TestIsWebAuthnError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "WebAuthnError",
			err:      NewWebAuthnError(ErrValidationFailed, "test error", ""),
			expected: true,
		},
		{
			name:     "Regular_Error",
			err:      assert.AnError,
			expected: false,
		},
		{
			name:     "Nil_Error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsWebAuthnError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGetWebAuthnError tests the GetWebAuthnError function
func TestGetWebAuthnError(t *testing.T) {
	webAuthnErr := NewWebAuthnError(ErrValidationFailed, "test error", "")
	
	tests := []struct {
		name     string
		err      error
		expected *WebAuthnError
	}{
		{
			name:     "WebAuthnError",
			err:      webAuthnErr,
			expected: webAuthnErr,
		},
		{
			name:     "Regular_Error",
			err:      assert.AnError,
			expected: nil,
		},
		{
			name:     "Nil_Error",
			err:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetWebAuthnError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSessionDataIsExpired tests the IsExpired method of SessionData
func TestSessionDataIsExpired(t *testing.T) {
	tests := []struct {
		name     string
		expires  time.Time
		expected bool
	}{
		{
			name:     "Future_Expiry",
			expires:  time.Now().Add(5 * time.Minute),
			expected: false,
		},
		{
			name:     "Past_Expiry",
			expires:  time.Now().Add(-5 * time.Minute),
			expected: true,
		},
		{
			name:     "Very_Close_Past",
			expires:  time.Now().Add(-1 * time.Millisecond),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SessionData{
				Expires: tt.expires,
			}
			result := session.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}