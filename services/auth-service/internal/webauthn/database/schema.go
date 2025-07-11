package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Migration represents a database migration
type Migration struct {
	Version     string
	Name        string
	UpSQL       string
	DownSQL     string
	AppliedAt   *time.Time
}

// Migrator handles database migrations
type Migrator struct {
	db *sql.DB
}

// NewMigrator creates a new Migrator instance
func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

// Initialize creates the schema_migrations table if it doesn't exist
func (m *Migrator) Initialize(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`
	
	_, err := m.db.ExecContext(ctx, query)
	return err
}

// ApplyMigration applies a single migration
func (m *Migrator) ApplyMigration(ctx context.Context, migration Migration) error {
	// Check if migration is already applied
	isApplied, err := m.IsMigrationApplied(ctx, migration.Version)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	
	if isApplied {
		return fmt.Errorf("migration %s is already applied", migration.Version)
	}
	
	// Start transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	
	// Execute migration SQL
	_, err = tx.ExecContext(ctx, migration.UpSQL)
	if err != nil {
		return fmt.Errorf("failed to execute migration %s: %w", migration.Version, err)
	}
	
	// Record migration as applied
	_, err = tx.ExecContext(ctx, 
		"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		migration.Version, migration.Name, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
	}
	
	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", migration.Version, err)
	}
	
	return nil
}

// IsMigrationApplied checks if a migration has been applied
func (m *Migrator) IsMigrationApplied(ctx context.Context, version string) (bool, error) {
	var count int
	err := m.db.QueryRowContext(ctx, 
		"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetAppliedMigrations returns all applied migrations
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	rows, err := m.db.QueryContext(ctx, 
		"SELECT version, name, applied_at FROM schema_migrations ORDER BY applied_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var migrations []Migration
	for rows.Next() {
		var migration Migration
		err := rows.Scan(&migration.Version, &migration.Name, &migration.AppliedAt)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, migration)
	}
	
	return migrations, nil
}

// GetWebAuthnCredentialsSchema returns the SQL for creating the webauthn_credentials table
func GetWebAuthnCredentialsSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT NOT NULL PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT DEFAULT 'none',
			transport TEXT DEFAULT '',
			user_present BOOLEAN NOT NULL DEFAULT 0,
			user_verified BOOLEAN NOT NULL DEFAULT 0,
			backup_eligible BOOLEAN NOT NULL DEFAULT 0,
			backup_state BOOLEAN NOT NULL DEFAULT 0,
			sign_count INTEGER NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`
}

// GetWebAuthnSessionsSchema returns the SQL for creating the webauthn_sessions table
func GetWebAuthnSessionsSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS webauthn_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			challenge BLOB NOT NULL,
			allowed_credential_ids TEXT DEFAULT '',
			user_verification TEXT DEFAULT 'preferred',
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`
}

// GetUsersTableSchema returns the SQL for creating the users table (for testing)
func GetUsersTableSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT UNIQUE,
			password_hash TEXT,
			email_verified BOOLEAN NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`
}

// GetWebAuthnIndexes returns the SQL statements for creating WebAuthn-related indexes
func GetWebAuthnIndexes() []string {
	return []string{
		// Indexes for webauthn_credentials table
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_created_at ON webauthn_credentials(created_at)",
		
		// Indexes for webauthn_sessions table
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_created_at ON webauthn_sessions(created_at)",
	}
}

// GetWebAuthnMigrations returns all WebAuthn-related migrations
func GetWebAuthnMigrations() []Migration {
	return []Migration{
		{
			Version: "001_create_webauthn_credentials",
			Name:    "Create WebAuthn credentials table",
			UpSQL:   GetWebAuthnCredentialsSchema(),
			DownSQL: "DROP TABLE IF EXISTS webauthn_credentials",
		},
		{
			Version: "002_create_webauthn_sessions",
			Name:    "Create WebAuthn sessions table",
			UpSQL:   GetWebAuthnSessionsSchema(),
			DownSQL: "DROP TABLE IF EXISTS webauthn_sessions",
		},
		{
			Version: "003_create_webauthn_indexes",
			Name:    "Create WebAuthn indexes",
			UpSQL:   createIndexesSQL(),
			DownSQL: dropIndexesSQL(),
		},
	}
}

// createIndexesSQL combines all index creation statements
func createIndexesSQL() string {
	indexes := GetWebAuthnIndexes()
	sql := ""
	for _, index := range indexes {
		sql += index + ";\n"
	}
	return sql
}

// dropIndexesSQL creates SQL to drop all WebAuthn indexes
func dropIndexesSQL() string {
	return `
		DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
		DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;
		DROP INDEX IF EXISTS idx_webauthn_credentials_created_at;
		DROP INDEX IF EXISTS idx_webauthn_sessions_user_id;
		DROP INDEX IF EXISTS idx_webauthn_sessions_expires_at;
		DROP INDEX IF EXISTS idx_webauthn_sessions_created_at;
	`
}

// ApplyAllWebAuthnMigrations applies all WebAuthn migrations in order
func ApplyAllWebAuthnMigrations(ctx context.Context, db *sql.DB) error {
	migrator := NewMigrator(db)
	
	// Initialize migration system
	if err := migrator.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize migrator: %w", err)
	}
	
	// Apply all migrations
	migrations := GetWebAuthnMigrations()
	for _, migration := range migrations {
		// Check if already applied
		isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
		if err != nil {
			return fmt.Errorf("failed to check migration %s: %w", migration.Version, err)
		}
		
		if !isApplied {
			if err := migrator.ApplyMigration(ctx, migration); err != nil {
				return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
			}
		}
	}
	
	return nil
}

// ValidateWebAuthnSchema validates that all required WebAuthn tables and indexes exist
func ValidateWebAuthnSchema(ctx context.Context, db *sql.DB) error {
	// Check required tables
	requiredTables := []string{"webauthn_credentials", "webauthn_sessions"}
	for _, tableName := range requiredTables {
		var name string
		err := db.QueryRowContext(ctx, 
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
		if err != nil {
			return fmt.Errorf("required table %s does not exist: %w", tableName, err)
		}
	}
	
	// Check required indexes
	requiredIndexes := []string{
		"idx_webauthn_credentials_user_id",
		"idx_webauthn_credentials_credential_id",
		"idx_webauthn_sessions_user_id",
		"idx_webauthn_sessions_expires_at",
	}
	
	for _, indexName := range requiredIndexes {
		var name string
		err := db.QueryRowContext(ctx, 
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", indexName).Scan(&name)
		if err != nil {
			return fmt.Errorf("required index %s does not exist: %w", indexName, err)
		}
	}
	
	return nil
}

// GetTableStats returns statistics about WebAuthn tables
func GetTableStats(ctx context.Context, db *sql.DB) (map[string]int, error) {
	stats := make(map[string]int)
	
	tables := []string{"webauthn_credentials", "webauthn_sessions"}
	for _, table := range tables {
		var count int
		err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("failed to get count for table %s: %w", table, err)
		}
		stats[table] = count
	}
	
	return stats, nil
}