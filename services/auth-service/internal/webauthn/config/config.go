package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"gopkg.in/yaml.v3"
)

// WebAuthnConfig represents the configuration for WebAuthn
type WebAuthnConfig struct {
	RPDisplayName string   `yaml:"rp_display_name" validate:"required" json:"rp_display_name"`
	RPID          string   `yaml:"rp_id" validate:"required" json:"rp_id"`
	RPOrigins     []string `yaml:"rp_origins" validate:"required,min=1" json:"rp_origins"`
	RPIcon        string   `yaml:"rp_icon" json:"rp_icon"`
	Timeout       int      `yaml:"timeout" validate:"gt=0" json:"timeout"`
	Debug         bool     `yaml:"debug" json:"debug"`
}

// YAMLConfig represents the YAML configuration structure
type YAMLConfig struct {
	WebAuthn WebAuthnConfig `yaml:"webauthn"`
}

// Validate validates the WebAuthn configuration
func (c *WebAuthnConfig) Validate() error {
	// Custom validations first (for more specific error messages)
	if c.RPDisplayName == "" {
		return errors.New("RPDisplayName is required")
	}

	if c.RPID == "" {
		return errors.New("RPID is required")
	}

	if len(c.RPOrigins) == 0 {
		return errors.New("RPOrigins is required")
	}

	if c.Timeout == 0 {
		return errors.New("Timeout must be greater than 0")
	}

	// Validate origin formats
	for _, origin := range c.RPOrigins {
		if _, err := url.Parse(origin); err != nil {
			return fmt.Errorf("invalid origin format: %s", origin)
		}
		if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return fmt.Errorf("invalid origin format: %s", origin)
		}
	}

	// Validate struct tags as fallback
	validate := validator.New()
	if err := validate.Struct(c); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	return nil
}

// ToWebAuthnConfig converts WebAuthnConfig to webauthn.Config
func (c *WebAuthnConfig) ToWebAuthnConfig() *webauthn.Config {
	return &webauthn.Config{
		RPDisplayName: c.RPDisplayName,
		RPID:          c.RPID,
		RPOrigins:     c.RPOrigins,
		RPIcon:        c.RPIcon,
		Timeout:       c.Timeout,
		Debug:         c.Debug,
	}
}

// LoadFromEnv loads WebAuthn configuration from environment variables
func LoadFromEnv() (*WebAuthnConfig, error) {
	config := &WebAuthnConfig{
		// Default values
		RPDisplayName: "Glen ID Platform",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		RPIcon:        "",
		Timeout:       60000,
		Debug:         false,
	}

	// Load from environment variables
	if val := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME"); val != "" {
		config.RPDisplayName = val
	}

	if val := os.Getenv("WEBAUTHN_RP_ID"); val != "" {
		config.RPID = val
	}

	if val := os.Getenv("WEBAUTHN_RP_ORIGINS"); val != "" {
		config.RPOrigins = strings.Split(val, ",")
		// Trim whitespace from origins
		for i, origin := range config.RPOrigins {
			config.RPOrigins[i] = strings.TrimSpace(origin)
		}
	}

	if val := os.Getenv("WEBAUTHN_RP_ICON"); val != "" {
		config.RPIcon = val
	}

	if val := os.Getenv("WEBAUTHN_TIMEOUT"); val != "" {
		timeout, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout value: %w", err)
		}
		config.Timeout = timeout
	}

	if val := os.Getenv("WEBAUTHN_DEBUG"); val != "" {
		debug, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid debug value: %w", err)
		}
		config.Debug = debug
	}

	return config, nil
}

// LoadFromYAML loads WebAuthn configuration from YAML content
func LoadFromYAML(yamlContent []byte) (*WebAuthnConfig, error) {
	var yamlConfig YAMLConfig
	
	if err := yaml.Unmarshal(yamlContent, &yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	config := &yamlConfig.WebAuthn

	// Set defaults if not provided
	if config.RPDisplayName == "" {
		config.RPDisplayName = "Glen ID Platform"
	}
	if config.RPID == "" {
		config.RPID = "localhost"
	}
	if len(config.RPOrigins) == 0 {
		config.RPOrigins = []string{"http://localhost:3000", "http://localhost:5173"}
	}
	if config.Timeout == 0 {
		config.Timeout = 60000
	}

	return config, nil
}

// LoadFromYAMLFile loads WebAuthn configuration from a YAML file
func LoadFromYAMLFile(filename string) (*WebAuthnConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	return LoadFromYAML(data)
}

// LoadConfig loads WebAuthn configuration with precedence: env > yaml > defaults
func LoadConfig(yamlFile string) (*WebAuthnConfig, error) {
	var config *WebAuthnConfig

	// Start with YAML config if file exists
	if yamlFile != "" {
		if _, err := os.Stat(yamlFile); err == nil {
			config, err = LoadFromYAMLFile(yamlFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load YAML config: %w", err)
			}
		}
	}

	// If no YAML config loaded, start with defaults
	if config == nil {
		config = &WebAuthnConfig{
			RPDisplayName: "Glen ID Platform",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
			RPIcon:        "",
			Timeout:       60000,
			Debug:         false,
		}
	}

	// Override with environment variables
	if val := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME"); val != "" {
		config.RPDisplayName = val
	}

	if val := os.Getenv("WEBAUTHN_RP_ID"); val != "" {
		config.RPID = val
	}

	if val := os.Getenv("WEBAUTHN_RP_ORIGINS"); val != "" {
		config.RPOrigins = strings.Split(val, ",")
		// Trim whitespace from origins
		for i, origin := range config.RPOrigins {
			config.RPOrigins[i] = strings.TrimSpace(origin)
		}
	}

	if val := os.Getenv("WEBAUTHN_RP_ICON"); val != "" {
		config.RPIcon = val
	}

	if val := os.Getenv("WEBAUTHN_TIMEOUT"); val != "" {
		timeout, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout value: %w", err)
		}
		config.Timeout = timeout
	}

	if val := os.Getenv("WEBAUTHN_DEBUG"); val != "" {
		debug, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid debug value: %w", err)
		}
		config.Debug = debug
	}

	return config, nil
}