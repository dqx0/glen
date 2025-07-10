package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthnConfigCreation tests WebAuthnConfig structure creation and validation
func TestWebAuthnConfigCreation(t *testing.T) {
	tests := []struct {
		name        string
		config      WebAuthnConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid_Config",
			config: WebAuthnConfig{
				RPDisplayName: "Test Application",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost:3000", "https://localhost:3000"},
				RPIcon:        "http://localhost:3000/icon.png",
				Timeout:       60000,
				Debug:         false,
			},
			expectError: false,
		},
		{
			name: "Missing_RPDisplayName",
			config: WebAuthnConfig{
				RPID:      "localhost",
				RPOrigins: []string{"http://localhost:3000"},
				Timeout:   60000,
			},
			expectError: true,
			errorMsg:    "RPDisplayName is required",
		},
		{
			name: "Missing_RPID",
			config: WebAuthnConfig{
				RPDisplayName: "Test App",
				RPOrigins:     []string{"http://localhost:3000"},
				Timeout:       60000,
			},
			expectError: true,
			errorMsg:    "RPID is required",
		},
		{
			name: "Missing_RPOrigins",
			config: WebAuthnConfig{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				Timeout:       60000,
			},
			expectError: true,
			errorMsg:    "RPOrigins is required",
		},
		{
			name: "Invalid_Timeout",
			config: WebAuthnConfig{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost:3000"},
				Timeout:       0,
			},
			expectError: true,
			errorMsg:    "Timeout must be greater than 0",
		},
		{
			name: "Invalid_Origin_Format",
			config: WebAuthnConfig{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				RPOrigins:     []string{"invalid-origin"},
				Timeout:       60000,
			},
			expectError: true,
			errorMsg:    "invalid origin format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err, "Config validation should fail")
				assert.Contains(t, err.Error(), tt.errorMsg, "Error message should contain expected text")
			} else {
				assert.NoError(t, err, "Config validation should pass")
			}
		})
	}
}

// TestWebAuthnConfigFromEnv tests environment variable loading
func TestWebAuthnConfigFromEnv(t *testing.T) {
	// Set up test environment variables
	testEnvVars := map[string]string{
		"WEBAUTHN_RP_DISPLAY_NAME": "Test From Env",
		"WEBAUTHN_RP_ID":           "test.example.com",
		"WEBAUTHN_RP_ORIGINS":      "https://test.example.com,https://app.example.com",
		"WEBAUTHN_RP_ICON":         "https://test.example.com/icon.png",
		"WEBAUTHN_TIMEOUT":         "120000",
		"WEBAUTHN_DEBUG":           "true",
	}

	// Set environment variables
	for key, value := range testEnvVars {
		os.Setenv(key, value)
	}

	// Clean up after test
	defer func() {
		for key := range testEnvVars {
			os.Unsetenv(key)
		}
	}()

	config, err := LoadFromEnv()
	require.NoError(t, err, "Loading from environment should not fail")

	assert.Equal(t, "Test From Env", config.RPDisplayName)
	assert.Equal(t, "test.example.com", config.RPID)
	assert.Equal(t, []string{"https://test.example.com", "https://app.example.com"}, config.RPOrigins)
	assert.Equal(t, "https://test.example.com/icon.png", config.RPIcon)
	assert.Equal(t, 120000, config.Timeout)
	assert.True(t, config.Debug)
}

// TestWebAuthnConfigFromEnvDefaults tests default values when env vars are not set
func TestWebAuthnConfigFromEnvDefaults(t *testing.T) {
	// Clean up any existing environment variables
	envVars := []string{
		"WEBAUTHN_RP_DISPLAY_NAME",
		"WEBAUTHN_RP_ID",
		"WEBAUTHN_RP_ORIGINS",
		"WEBAUTHN_RP_ICON",
		"WEBAUTHN_TIMEOUT",
		"WEBAUTHN_DEBUG",
	}

	for _, envVar := range envVars {
		os.Unsetenv(envVar)
	}

	config, err := LoadFromEnv()
	require.NoError(t, err, "Loading from environment should not fail")

	// Check default values
	assert.Equal(t, "Glen ID Platform", config.RPDisplayName)
	assert.Equal(t, "localhost", config.RPID)
	assert.Equal(t, []string{"http://localhost:3000", "http://localhost:5173"}, config.RPOrigins)
	assert.Equal(t, "", config.RPIcon)
	assert.Equal(t, 60000, config.Timeout)
	assert.False(t, config.Debug)
}

// TestWebAuthnConfigFromYAML tests YAML configuration loading
func TestWebAuthnConfigFromYAML(t *testing.T) {
	yamlContent := `
webauthn:
  rp_display_name: "Test YAML App"
  rp_id: "yaml.example.com"
  rp_origins:
    - "https://yaml.example.com"
    - "https://app.yaml.example.com"
  rp_icon: "https://yaml.example.com/icon.png"
  timeout: 90000
  debug: true
`

	config, err := LoadFromYAML([]byte(yamlContent))
	require.NoError(t, err, "Loading from YAML should not fail")

	assert.Equal(t, "Test YAML App", config.RPDisplayName)
	assert.Equal(t, "yaml.example.com", config.RPID)
	assert.Equal(t, []string{"https://yaml.example.com", "https://app.yaml.example.com"}, config.RPOrigins)
	assert.Equal(t, "https://yaml.example.com/icon.png", config.RPIcon)
	assert.Equal(t, 90000, config.Timeout)
	assert.True(t, config.Debug)
}

// TestWebAuthnConfigFromYAMLFile tests YAML file loading
func TestWebAuthnConfigFromYAMLFile(t *testing.T) {
	// Create temporary YAML file
	yamlContent := `
webauthn:
  rp_display_name: "Test File App"
  rp_id: "file.example.com"
  rp_origins:
    - "https://file.example.com"
  timeout: 45000
  debug: false
`

	tmpFile, err := os.CreateTemp("", "webauthn-test-*.yaml")
	require.NoError(t, err, "Creating temp file should not fail")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(yamlContent))
	require.NoError(t, err, "Writing to temp file should not fail")
	tmpFile.Close()

	config, err := LoadFromYAMLFile(tmpFile.Name())
	require.NoError(t, err, "Loading from YAML file should not fail")

	assert.Equal(t, "Test File App", config.RPDisplayName)
	assert.Equal(t, "file.example.com", config.RPID)
	assert.Equal(t, []string{"https://file.example.com"}, config.RPOrigins)
	assert.Equal(t, 45000, config.Timeout)
	assert.False(t, config.Debug)
}

// TestWebAuthnConfigToWebAuthnConfig tests conversion to webauthn.Config
func TestWebAuthnConfigToWebAuthnConfig(t *testing.T) {
	config := WebAuthnConfig{
		RPDisplayName: "Test Conversion",
		RPID:          "convert.example.com",
		RPOrigins:     []string{"https://convert.example.com"},
		RPIcon:        "https://convert.example.com/icon.png",
		Timeout:       75000,
		Debug:         true,
	}

	webAuthnConfig := config.ToWebAuthnConfig()

	assert.Equal(t, config.RPDisplayName, webAuthnConfig.RPDisplayName)
	assert.Equal(t, config.RPID, webAuthnConfig.RPID)
	assert.Equal(t, config.RPOrigins, webAuthnConfig.RPOrigins)
	assert.Equal(t, config.RPIcon, webAuthnConfig.RPIcon)
	assert.Equal(t, config.Timeout, webAuthnConfig.Timeout)
	assert.Equal(t, config.Debug, webAuthnConfig.Debug)
}

// TestWebAuthnConfigPrecedence tests configuration precedence (env > yaml > defaults)
func TestWebAuthnConfigPrecedence(t *testing.T) {
	// Create YAML config
	yamlContent := `
webauthn:
  rp_display_name: "YAML App"
  rp_id: "yaml.example.com"
  rp_origins:
    - "https://yaml.example.com"
  timeout: 90000
  debug: false
`

	tmpFile, err := os.CreateTemp("", "webauthn-precedence-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tmpFile.Close()

	// Set environment variables (should override YAML)
	os.Setenv("WEBAUTHN_RP_DISPLAY_NAME", "Env App")
	os.Setenv("WEBAUTHN_TIMEOUT", "120000")
	defer func() {
		os.Unsetenv("WEBAUTHN_RP_DISPLAY_NAME")
		os.Unsetenv("WEBAUTHN_TIMEOUT")
	}()

	config, err := LoadConfig(tmpFile.Name())
	require.NoError(t, err, "Loading config with precedence should not fail")

	// Environment variable should override YAML
	assert.Equal(t, "Env App", config.RPDisplayName)
	assert.Equal(t, 120000, config.Timeout)

	// YAML values should be used where env vars are not set
	assert.Equal(t, "yaml.example.com", config.RPID)
	assert.Equal(t, []string{"https://yaml.example.com"}, config.RPOrigins)
	assert.False(t, config.Debug)
}