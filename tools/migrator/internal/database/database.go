package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/dqx0/glen/migrator/internal/config"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// DB wraps the database connection with helper methods
type DB struct {
	*sql.DB
	config *config.Config
}

// NewDB creates a new database connection
func NewDB(cfg *config.Config) (*DB, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{
		DB:     db,
		config: cfg,
	}, nil
}

// CreateMigrationTable creates the migrations table if it doesn't exist
func (db *DB) CreateMigrationTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			dirty BOOLEAN NOT NULL DEFAULT FALSE,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// GetAppliedMigrations returns a list of applied migration versions
func (db *DB) GetAppliedMigrations() ([]string, error) {
	query := `
		SELECT version 
		FROM schema_migrations 
		WHERE dirty = FALSE 
		ORDER BY version
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %w", err)
		}
		versions = append(versions, version)
	}

	return versions, nil
}

// MarkMigrationApplied marks a migration as applied
func (db *DB) MarkMigrationApplied(version string) error {
	query := `
		INSERT INTO schema_migrations (version, dirty) 
		VALUES ($1, FALSE) 
		ON CONFLICT (version) DO UPDATE SET 
			dirty = FALSE, 
			applied_at = NOW()
	`

	_, err := db.Exec(query, version)
	if err != nil {
		return fmt.Errorf("failed to mark migration as applied: %w", err)
	}

	return nil
}

// MarkMigrationDirty marks a migration as dirty (failed)
func (db *DB) MarkMigrationDirty(version string) error {
	query := `
		INSERT INTO schema_migrations (version, dirty) 
		VALUES ($1, TRUE) 
		ON CONFLICT (version) DO UPDATE SET dirty = TRUE
	`

	_, err := db.Exec(query, version)
	if err != nil {
		return fmt.Errorf("failed to mark migration as dirty: %w", err)
	}

	return nil
}

// RemoveMigration removes a migration record
func (db *DB) RemoveMigration(version string) error {
	query := `DELETE FROM schema_migrations WHERE version = $1`

	_, err := db.Exec(query, version)
	if err != nil {
		return fmt.Errorf("failed to remove migration: %w", err)
	}

	return nil
}

// IsConnected checks if the database connection is still alive
func (db *DB) IsConnected() bool {
	return db.Ping() == nil
}