package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationOrder tests that migrations are applied in the correct order
func TestMigrationOrder(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize migration system
	err = migrator.Initialize(ctx)
	require.NoError(t, err)

	// Apply migrations one by one and verify order
	migrations := GetWebAuthnMigrations()
	
	for i, migration := range migrations {
		t.Run(migration.Name, func(t *testing.T) {
			err := migrator.ApplyMigration(ctx, migration)
			assert.NoError(t, err, "Migration should apply successfully")

			// Verify migration was recorded
			isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
			assert.NoError(t, err)
			assert.True(t, isApplied, "Migration should be marked as applied")

			// Verify that we have the expected number of applied migrations
			appliedMigrations, err := migrator.GetAppliedMigrations(ctx)
			assert.NoError(t, err)
			assert.Len(t, appliedMigrations, i+1, "Should have %d applied migrations", i+1)
		})
	}
}

// TestMigrationRollback tests migration rollback functionality
func TestMigrationRollback(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize and apply first migration
	err = migrator.Initialize(ctx)
	require.NoError(t, err)

	migrations := GetWebAuthnMigrations()
	migration := migrations[0]

	err = migrator.ApplyMigration(ctx, migration)
	require.NoError(t, err)

	// Test rollback functionality (if implemented)
	t.Run("Rollback_Migration", func(t *testing.T) {
		// For now, we'll test manual rollback
		_, err := db.ExecContext(ctx, migration.DownSQL)
		assert.NoError(t, err, "Rollback SQL should execute successfully")

		// Manually remove from migrations table
		_, err = db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version = ?", migration.Version)
		assert.NoError(t, err)

		// Verify migration is no longer applied
		isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
		assert.NoError(t, err)
		assert.False(t, isApplied, "Migration should not be marked as applied after rollback")
	})
}

// TestMigrationIdempotency tests that migrations can be run multiple times safely
func TestMigrationIdempotency(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Test that ApplyAllWebAuthnMigrations can be called multiple times
	t.Run("Multiple_ApplyAllWebAuthnMigrations_Calls", func(t *testing.T) {
		// First application
		err := ApplyAllWebAuthnMigrations(ctx, db)
		assert.NoError(t, err, "First application should succeed")

		// Second application should also succeed (idempotent)
		err = ApplyAllWebAuthnMigrations(ctx, db)
		assert.NoError(t, err, "Second application should succeed")

		// Third application should also succeed
		err = ApplyAllWebAuthnMigrations(ctx, db)
		assert.NoError(t, err, "Third application should succeed")

		// Verify all migrations are still applied
		migrator := NewMigrator(db)
		migrations := GetWebAuthnMigrations()
		
		for _, migration := range migrations {
			isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
			assert.NoError(t, err)
			assert.True(t, isApplied, "Migration %s should still be applied", migration.Version)
		}
	})
}

// TestMigrationTransactionRollback tests that failed migrations are rolled back
func TestMigrationTransactionRollback(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()
	migrator := NewMigrator(db)

	err = migrator.Initialize(ctx)
	require.NoError(t, err)

	// Create a migration with invalid SQL
	invalidMigration := Migration{
		Version: "999_invalid_migration",
		Name:    "Invalid Migration",
		UpSQL:   "INVALID SQL STATEMENT;",
		DownSQL: "",
	}

	t.Run("Failed_Migration_Should_Rollback", func(t *testing.T) {
		err := migrator.ApplyMigration(ctx, invalidMigration)
		assert.Error(t, err, "Invalid migration should fail")

		// Verify migration was not recorded as applied
		isApplied, err := migrator.IsMigrationApplied(ctx, invalidMigration.Version)
		assert.NoError(t, err)
		assert.False(t, isApplied, "Failed migration should not be marked as applied")
	})
}

// TestSchemaValidation tests the schema validation functionality
func TestSchemaValidation(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	t.Run("Validation_Before_Migration", func(t *testing.T) {
		// Validation should fail before migrations are applied
		err := ValidateWebAuthnSchema(ctx, db)
		assert.Error(t, err, "Schema validation should fail before migrations")
	})

	t.Run("Validation_After_Migration", func(t *testing.T) {
		// Apply migrations
		err := ApplyAllWebAuthnMigrations(ctx, db)
		require.NoError(t, err)

		// Validation should succeed after migrations
		err = ValidateWebAuthnSchema(ctx, db)
		assert.NoError(t, err, "Schema validation should succeed after migrations")
	})
}

// TestTableStats tests the table statistics functionality
func TestTableStats(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Apply migrations first
	err = ApplyAllWebAuthnMigrations(ctx, db)
	require.NoError(t, err)

	t.Run("Empty_Tables_Stats", func(t *testing.T) {
		stats, err := GetTableStats(ctx, db)
		assert.NoError(t, err, "Getting table stats should succeed")

		expectedTables := []string{"webauthn_credentials", "webauthn_sessions"}
		for _, table := range expectedTables {
			count, exists := stats[table]
			assert.True(t, exists, "Stats should include table %s", table)
			assert.Equal(t, 0, count, "Empty table should have 0 rows")
		}
	})

	t.Run("Tables_With_Data_Stats", func(t *testing.T) {
		// Create users table first
		usersSchema := GetUsersTableSchema()
		_, err := db.ExecContext(ctx, usersSchema)
		require.NoError(t, err)

		// Insert test data
		_, err = db.ExecContext(ctx, `
			INSERT INTO users (id, username, email, password_hash, email_verified, status, created_at, updated_at)
			VALUES ('test-user', 'testuser', 'test@example.com', 'hash', 0, 'active', datetime('now'), datetime('now'))
		`)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO webauthn_credentials (
				id, user_id, credential_id, public_key, attestation_type, 
				transport, user_present, user_verified, backup_eligible, backup_state, 
				sign_count, clone_warning, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
		`,
			"cred-1", "test-user", []byte("cred-id-1"), []byte("pub-key-1"),
			"none", "usb", true, true, false, false, 0, false)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO webauthn_sessions (
				id, user_id, challenge, allowed_credential_ids, user_verification, expires_at, created_at
			) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		`,
			"session-1", "test-user", []byte("challenge-1"), "", "preferred", time.Now().Add(5*time.Minute))
		require.NoError(t, err)

		// Get stats
		stats, err := GetTableStats(ctx, db)
		assert.NoError(t, err)

		assert.Equal(t, 1, stats["webauthn_credentials"], "Should have 1 credential")
		assert.Equal(t, 1, stats["webauthn_sessions"], "Should have 1 session")
	})
}

// TestMigrationMetadata tests migration metadata handling
func TestMigrationMetadata(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()
	migrator := NewMigrator(db)

	err = migrator.Initialize(ctx)
	require.NoError(t, err)

	// Apply some migrations
	migrations := GetWebAuthnMigrations()
	for _, migration := range migrations[:2] { // Apply first 2 migrations
		err := migrator.ApplyMigration(ctx, migration)
		require.NoError(t, err)
	}

	t.Run("Get_Applied_Migrations_Metadata", func(t *testing.T) {
		appliedMigrations, err := migrator.GetAppliedMigrations(ctx)
		assert.NoError(t, err)
		assert.Len(t, appliedMigrations, 2, "Should have 2 applied migrations")

		// Verify metadata
		for i, applied := range appliedMigrations {
			assert.Equal(t, migrations[i].Version, applied.Version)
			assert.Equal(t, migrations[i].Name, applied.Name)
			// Production schema doesn't have applied_at column, so AppliedAt will be nil
			assert.Nil(t, applied.AppliedAt, "AppliedAt should be nil in production schema")
		}
	})

	t.Run("Check_Individual_Migration_Status", func(t *testing.T) {
		// Check applied migrations
		for _, migration := range migrations[:2] {
			isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
			assert.NoError(t, err)
			assert.True(t, isApplied, "Migration %s should be applied", migration.Version)
		}

		// Check unapplied migrations
		for _, migration := range migrations[2:] {
			isApplied, err := migrator.IsMigrationApplied(ctx, migration.Version)
			assert.NoError(t, err)
			assert.False(t, isApplied, "Migration %s should not be applied", migration.Version)
		}
	})
}

// BenchmarkMigrationApplication benchmarks the migration application process
func BenchmarkMigrationApplication(b *testing.B) {
	for i := 0; i < b.N; i++ {
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			b.Fatal(err)
		}

		ctx := context.Background()
		err = ApplyAllWebAuthnMigrations(ctx, db)
		if err != nil {
			b.Fatal(err)
		}

		db.Close()
	}
}

// BenchmarkSchemaValidation benchmarks the schema validation process
func BenchmarkSchemaValidation(b *testing.B) {
	// Setup database once
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	err = ApplyAllWebAuthnMigrations(ctx, db)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := ValidateWebAuthnSchema(ctx, db)
		if err != nil {
			b.Fatal(err)
		}
	}
}