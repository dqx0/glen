package config

import (
	"fmt"
	"os"
)

// Config holds the configuration for the migrator
type Config struct {
	DatabaseURL  string
	Host         string
	Port         string
	User         string
	Password     string
	Database     string
	SSLMode      string
	Environment  string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	config := &Config{
		Host:        getEnv("DB_HOST", "localhost"),
		Port:        getEnv("DB_PORT", "5432"),
		User:        getEnv("DB_USER", "glen_dev"),
		Password:    getEnv("DB_PASSWORD", "glen_dev_pass"),
		Database:    getEnv("DB_NAME", "glen_dev"),
		SSLMode:     getEnv("DB_SSLMODE", "disable"),
		Environment: getEnv("ENV", "development"),
	}

	// Build DATABASE_URL if not provided
	if config.DatabaseURL = getEnv("DATABASE_URL", ""); config.DatabaseURL == "" {
		config.DatabaseURL = fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=%s",
			config.User,
			config.Password,
			config.Host,
			config.Port,
			config.Database,
			config.SSLMode,
		)
	}

	return config
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// IsProduction returns true if running in production
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in development
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsTest returns true if running in test mode
func (c *Config) IsTest() bool {
	return c.Environment == "test"
}