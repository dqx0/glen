package database

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebAuthnCredentialsTableSchema tests the WebAuthn credentials table schema
func TestWebAuthnCredentialsTableSchema(t *testing.T) {
	ctx := context.Background()

	// Test that the schema can be created successfully
	t.Run("Create_WebAuthn_Credentials_Table", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		schema := GetWebAuthnCredentialsSchema()
		
		_, err = db.ExecContext(ctx, schema)
		assert.NoError(t, err, "WebAuthn credentials table creation should succeed")
	})

	// Test that all required columns exist
	t.Run("Verify_Table_Columns", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		schema := GetWebAuthnCredentialsSchema()
		_, err = db.ExecContext(ctx, schema)
		require.NoError(t, err)

		// Check table structure
		rows, err := db.QueryContext(ctx, "PRAGMA table_info(webauthn_credentials)")
		require.NoError(t, err)
		defer rows.Close()

		expectedColumns := map[string]bool{
			"id":               false,
			"user_id":          false,
			"credential_id":    false,
			"public_key":       false,
			"attestation_type": false,
			"transport":        false,
			"user_present":     false,
			"user_verified":    false,
			"backup_eligible":  false,
			"backup_state":     false,
			"sign_count":       false,
			"clone_warning":    false,
			"created_at":       false,
			"updated_at":       false,
		}

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull, pk int
			var defaultValue sql.NullString

			err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
			require.NoError(t, err)

			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		// Verify all expected columns were found
		for columnName, found := range expectedColumns {
			assert.True(t, found, "Column %s should exist in webauthn_credentials table", columnName)
		}
	})

	// Test that indexes can be created
	t.Run("Create_WebAuthn_Indexes", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		// Create both tables required for all indexes
		credentialsSchema := GetWebAuthnCredentialsSchema()
		_, err = db.ExecContext(ctx, credentialsSchema)
		require.NoError(t, err)

		sessionsSchema := GetWebAuthnSessionsSchema()
		_, err = db.ExecContext(ctx, sessionsSchema)
		require.NoError(t, err)

		indexes := GetWebAuthnIndexes()
		for _, indexSQL := range indexes {
			_, err := db.ExecContext(ctx, indexSQL)
			assert.NoError(t, err, "Index creation should succeed: %s", indexSQL)
		}
	})

	// Test foreign key constraints
	t.Run("Verify_Foreign_Key_Constraints", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		// First create users table
		usersSchema := GetUsersTableSchema()
		_, err = db.ExecContext(ctx, usersSchema)
		require.NoError(t, err)

		// Then create webauthn_credentials table
		schema := GetWebAuthnCredentialsSchema()
		_, err = db.ExecContext(ctx, schema)
		require.NoError(t, err)

		// Enable foreign key constraints
		_, err = db.ExecContext(ctx, "PRAGMA foreign_keys = ON")
		require.NoError(t, err)

		// Try to insert a credential with non-existent user_id
		insertQuery := `
			INSERT INTO webauthn_credentials (
				id, user_id, credential_id, public_key, attestation_type, 
				transport, user_present, user_verified, backup_eligible, backup_state, 
				sign_count, clone_warning, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`

		_, err = db.ExecContext(ctx, insertQuery,
			"test-cred-id", "non-existent-user-id", []byte("cred-id"), []byte("public-key"),
			"none", "usb", true, true, false, false, 0, false)

		// This should fail due to foreign key constraint
		assert.Error(t, err, "Insert with non-existent user_id should fail")
	})
}

// TestWebAuthnSessionsTableSchema tests the WebAuthn sessions table schema
func TestWebAuthnSessionsTableSchema(t *testing.T) {
	ctx := context.Background()

	// Test that the schema can be created successfully
	t.Run("Create_WebAuthn_Sessions_Table", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		schema := GetWebAuthnSessionsSchema()
		
		_, err = db.ExecContext(ctx, schema)
		assert.NoError(t, err, "WebAuthn sessions table creation should succeed")
	})

	// Test that all required columns exist
	t.Run("Verify_Table_Columns", func(t *testing.T) {
		db, err := sql.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		defer db.Close()

		schema := GetWebAuthnSessionsSchema()
		_, err = db.ExecContext(ctx, schema)
		require.NoError(t, err)

		// Check table structure
		rows, err := db.QueryContext(ctx, "PRAGMA table_info(webauthn_sessions)")
		require.NoError(t, err)
		defer rows.Close()

		expectedColumns := map[string]bool{
			"id":                        false,
			"user_id":                   false,
			"challenge":                 false,
			"allowed_credential_ids":    false,
			"user_verification":         false,
			"expires_at":                false,
			"created_at":                false,
		}

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull, pk int
			var defaultValue sql.NullString

			err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
			require.NoError(t, err)

			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		// Verify all expected columns were found
		for columnName, found := range expectedColumns {
			assert.True(t, found, "Column %s should exist in webauthn_sessions table", columnName)
		}
	})
}

// TestMigrationSystem tests the migration system
func TestMigrationSystem(t *testing.T) {
	// Create in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to create test database")
	defer db.Close()

	ctx := context.Background()

	t.Run("Initialize_Migration_System", func(t *testing.T) {
		migrator := NewMigrator(db)
		
		err := migrator.Initialize(ctx)
		assert.NoError(t, err, "Migration system initialization should succeed")

		// Verify migrations table exists
		var tableName string
		err = db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'").Scan(&tableName)
		assert.NoError(t, err, "schema_migrations table should exist")
		assert.Equal(t, "schema_migrations", tableName)
	})

	t.Run("Apply_WebAuthn_Migrations", func(t *testing.T) {
		migrator := NewMigrator(db)
		
		err := migrator.Initialize(ctx)
		require.NoError(t, err)

		// Get all WebAuthn migrations
		migrations := GetWebAuthnMigrations()
		assert.NotEmpty(t, migrations, "Should have WebAuthn migrations")

		// Apply migrations
		for _, migration := range migrations {
			err := migrator.ApplyMigration(ctx, migration)
			assert.NoError(t, err, "Migration should apply successfully: %s", migration.Name)
		}

		// Verify tables were created
		tables := []string{"webauthn_credentials", "webauthn_sessions"}
		for _, tableName := range tables {
			var name string
			err = db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
			assert.NoError(t, err, "Table %s should exist after migration", tableName)
		}
	})

	t.Run("Check_Migration_Status", func(t *testing.T) {
		migrator := NewMigrator(db)
		
		err := migrator.Initialize(ctx)
		require.NoError(t, err)

		// Apply migrations
		migrations := GetWebAuthnMigrations()
		for _, migration := range migrations {
			err := migrator.ApplyMigration(ctx, migration)
			require.NoError(t, err)
		}

		// Check status
		appliedMigrations, err := migrator.GetAppliedMigrations(ctx)
		assert.NoError(t, err, "Should be able to get applied migrations")
		assert.Len(t, appliedMigrations, len(migrations), "All migrations should be applied")

		// Check if specific migration is applied
		for _, migration := range migrations {
			isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
			assert.NoError(t, err, "Should be able to check migration status")
			assert.True(t, isApplied, "Migration %s should be applied", migration.Name)
		}
	})

	t.Run("Prevent_Duplicate_Migration_Application", func(t *testing.T) {
		migrator := NewMigrator(db)
		
		err := migrator.Initialize(ctx)
		require.NoError(t, err)

		// Apply migrations first time
		migrations := GetWebAuthnMigrations()
		migration := migrations[0] // Take first migration

		err = migrator.ApplyMigration(ctx, migration)
		require.NoError(t, err)

		// Try to apply same migration again
		err = migrator.ApplyMigration(ctx, migration)
		assert.Error(t, err, "Should not be able to apply same migration twice")
	})
}

// TestDatabaseConstraints tests database constraints and data integrity
func TestDatabaseConstraints(t *testing.T) {
	// Create in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to create test database")
	defer db.Close()

	ctx := context.Background()

	// Setup tables
	usersSchema := GetUsersTableSchema()
	_, err = db.ExecContext(ctx, usersSchema)
	require.NoError(t, err)

	webauthnSchema := GetWebAuthnCredentialsSchema()
	_, err = db.ExecContext(ctx, webauthnSchema)
	require.NoError(t, err)

	// Enable foreign key constraints
	_, err = db.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	require.NoError(t, err)

	t.Run("Unique_Constraint_On_Credential_ID", func(t *testing.T) {
		// Insert a test user first
		_, err := db.ExecContext(ctx, `
			INSERT INTO users (id, username, email, password_hash, email_verified, status, created_at, updated_at)
			VALUES ('test-user-1', 'testuser1', 'test1@example.com', 'hash', 0, 'active', datetime('now'), datetime('now'))
		`)
		require.NoError(t, err)

		// Insert first credential
		_, err = db.ExecContext(ctx, `
			INSERT INTO webauthn_credentials (
				id, user_id, credential_id, public_key, attestation_type, 
				transport, user_present, user_verified, backup_eligible, backup_state, 
				sign_count, clone_warning, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`,
			"cred-1", "test-user-1", []byte("unique-cred-id"), []byte("public-key-1"),
			"none", "usb", true, true, false, false, 0, false)
		require.NoError(t, err)

		// Try to insert another credential with same credential_id
		_, err = db.ExecContext(ctx, `
			INSERT INTO webauthn_credentials (
				id, user_id, credential_id, public_key, attestation_type, 
				transport, user_present, user_verified, backup_eligible, backup_state, 
				sign_count, clone_warning, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`,
			"cred-2", "test-user-1", []byte("unique-cred-id"), []byte("public-key-2"),
			"none", "nfc", true, true, false, false, 0, false)

		// This should fail due to unique constraint
		assert.Error(t, err, "Duplicate credential_id should be rejected")
	})

	t.Run("Not_Null_Constraints", func(t *testing.T) {
		// Try to insert credential with NULL required fields
		testCases := []struct {
			name     string
			id       interface{}
			userID   interface{}
			credID   interface{}
			pubKey   interface{}
		}{
			{"Null_ID", nil, "test-user-1", []byte("cred-id"), []byte("pub-key")},
			{"Null_UserID", "cred-id", nil, []byte("cred-id"), []byte("pub-key")},
			{"Null_CredentialID", "cred-id", "test-user-1", nil, []byte("pub-key")},
			{"Null_PublicKey", "cred-id", "test-user-1", []byte("cred-id"), nil},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := db.ExecContext(ctx, `
					INSERT INTO webauthn_credentials (
						id, user_id, credential_id, public_key, attestation_type, 
						transport, user_present, user_verified, backup_eligible, backup_state, 
						sign_count, clone_warning, created_at, updated_at
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
				`,
					tc.id, tc.userID, tc.credID, tc.pubKey,
					"none", "usb", true, true, false, false, 0, false)

				assert.Error(t, err, "Insert with NULL required field should fail")
			})
		}
	})
}