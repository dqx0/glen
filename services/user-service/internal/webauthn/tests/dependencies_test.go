package tests

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthnLibraryCompatibility tests that all WebAuthn libraries work correctly
func TestWebAuthnLibraryCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{"CBOR_Encoding", testCBOREncoding},
		{"WebAuthn_Creation", testWebAuthnCreation},
		{"Validator_Functionality", testValidatorFunctionality},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.testFunc)
	}
}

// testCBOREncoding tests CBOR encoding/decoding functionality
func testCBOREncoding(t *testing.T) {
	// Test CBOR encoding/decoding functionality
	testData := map[string]interface{}{
		"challenge": []byte("test-challenge-data-12345678901234567890"),
		"origin":    "https://example.com",
		"type":      "webauthn.create",
		"number":    42,
		"boolean":   true,
	}

	// Encode to CBOR
	encoded, err := cbor.Marshal(testData)
	require.NoError(t, err, "CBOR encoding should not fail")
	assert.Greater(t, len(encoded), 0, "Encoded data should not be empty")

	// Decode from CBOR
	var decoded map[string]interface{}
	err = cbor.Unmarshal(encoded, &decoded)
	require.NoError(t, err, "CBOR decoding should not fail")

	// Verify data integrity
	assert.Equal(t, testData["origin"], decoded["origin"])
	assert.Equal(t, testData["type"], decoded["type"])
	// CBOR converts int to uint64, so we need to check the converted value
	assert.Equal(t, uint64(42), decoded["number"])
	assert.Equal(t, testData["boolean"], decoded["boolean"])

	// Verify byte array handling
	decodedChallenge, ok := decoded["challenge"].([]byte)
	require.True(t, ok, "Challenge should be decoded as byte slice")
	assert.Equal(t, testData["challenge"], decodedChallenge)
}

// testWebAuthnCreation tests WebAuthn library initialization
func testWebAuthnCreation(t *testing.T) {
	// Test WebAuthn configuration creation
	config := &webauthn.Config{
		RPDisplayName: "Test Application",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		RPIcon:        "http://localhost:3000/icon.png",
	}

	// Create WebAuthn instance
	webAuthn, err := webauthn.New(config)
	require.NoError(t, err, "WebAuthn creation should not fail")
	require.NotNil(t, webAuthn, "WebAuthn instance should not be nil")

	// Verify configuration
	assert.Equal(t, config.RPDisplayName, webAuthn.Config.RPDisplayName)
	assert.Equal(t, config.RPID, webAuthn.Config.RPID)
	assert.Equal(t, config.RPOrigins, webAuthn.Config.RPOrigins)
}

// testValidatorFunctionality tests validator library functionality
func testValidatorFunctionality(t *testing.T) {
	type TestStruct struct {
		ID       string `validate:"required,uuid4"`
		Username string `validate:"required,min=3,max=50"`
		Email    string `validate:"omitempty,email"`
		Age      int    `validate:"gte=0,lte=150"`
	}

	validator := validator.New()

	tests := []struct {
		name        string
		data        TestStruct
		expectError bool
	}{
		{
			name: "Valid_Data",
			data: TestStruct{
				ID:       "550e8400-e29b-41d4-a716-446655440000",
				Username: "testuser",
				Email:    "test@example.com",
				Age:      25,
			},
			expectError: false,
		},
		{
			name: "Invalid_UUID",
			data: TestStruct{
				ID:       "invalid-uuid",
				Username: "testuser",
				Email:    "test@example.com",
				Age:      25,
			},
			expectError: true,
		},
		{
			name: "Username_Too_Short",
			data: TestStruct{
				ID:       "550e8400-e29b-41d4-a716-446655440000",
				Username: "ab",
				Email:    "test@example.com",
				Age:      25,
			},
			expectError: true,
		},
		{
			name: "Invalid_Email",
			data: TestStruct{
				ID:       "550e8400-e29b-41d4-a716-446655440000",
				Username: "testuser",
				Email:    "invalid-email",
				Age:      25,
			},
			expectError: true,
		},
		{
			name: "Empty_Email_Valid",
			data: TestStruct{
				ID:       "550e8400-e29b-41d4-a716-446655440000",
				Username: "testuser",
				Email:    "", // Empty email should be valid due to omitempty
				Age:      25,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Struct(tt.data)

			if tt.expectError {
				assert.Error(t, err, "Validation should fail for invalid data")
			} else {
				assert.NoError(t, err, "Validation should pass for valid data")
			}
		})
	}
}

// TestCryptographicOperations tests basic cryptographic operations
func TestCryptographicOperations(t *testing.T) {
	// Test random bytes generation
	challenge := make([]byte, 32)
	n, err := rand.Read(challenge)
	require.NoError(t, err, "Random bytes generation should not fail")
	assert.Equal(t, 32, n, "Should generate exactly 32 bytes")

	// Verify randomness (basic check - no all zeros)
	allZeros := true
	for _, b := range challenge {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "Generated bytes should not be all zeros")

	// Test that multiple generations produce different results
	challenge2 := make([]byte, 32)
	_, err = rand.Read(challenge2)
	require.NoError(t, err)
	assert.NotEqual(t, challenge, challenge2, "Multiple generations should produce different results")
}

// TestLibraryVersions tests that all libraries are at expected versions
func TestLibraryVersions(t *testing.T) {
	// This test ensures we're using compatible versions
	// In a real environment, you'd check specific version requirements
	t.Log("Testing library compatibility...")

	// Test WebAuthn library basic functionality
	config := &webauthn.Config{
		RPDisplayName: "Version Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000"},
	}

	webAuthn, err := webauthn.New(config)
	require.NoError(t, err, "WebAuthn library should be compatible")
	require.NotNil(t, webAuthn, "WebAuthn instance should be created")

	// Test CBOR library basic functionality
	testData := map[string]string{"test": "data"}
	encoded, err := cbor.Marshal(testData)
	require.NoError(t, err, "CBOR library should be compatible")

	var decoded map[string]string
	err = cbor.Unmarshal(encoded, &decoded)
	require.NoError(t, err, "CBOR decode should work")
	assert.Equal(t, testData, decoded, "Data should be preserved")

	// Test validator library basic functionality
	validator := validator.New()
	type SimpleTest struct {
		Field string `validate:"required"`
	}

	err = validator.Struct(SimpleTest{Field: "value"})
	assert.NoError(t, err, "Validator library should be compatible")

	err = validator.Struct(SimpleTest{Field: ""})
	assert.Error(t, err, "Validator should catch validation errors")

	t.Log("All libraries are compatible and functioning correctly")
}