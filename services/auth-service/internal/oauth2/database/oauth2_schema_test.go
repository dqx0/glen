package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	
	// Create users table first (required for foreign keys)
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT UNIQUE,
			password_hash TEXT,
			email_verified BOOLEAN NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)
	
	return db
}

func TestGetOAuth2ClientsSchema(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Execute schema creation
	_, err := db.Exec(GetOAuth2ClientsSchema())
	assert.NoError(t, err)
	
	// Verify table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth2_clients'").Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "oauth2_clients", tableName)
	
	// Test inserting a record
	_, err = db.Exec(`
		INSERT INTO users (id, username, email, password_hash) 
		VALUES ('user-1', 'testuser', 'test@example.com', 'hash')
	`)
	require.NoError(t, err)
	
	_, err = db.Exec(`
		INSERT INTO oauth2_clients (
			id, user_id, client_id, client_secret_hash, name, description,
			redirect_uris, scopes, grant_types, response_types, is_public, is_active
		) VALUES (
			'client-1', 'user-1', 'test_client_id', 'secret_hash', 'Test Client', 'Test Description',
			'["http://localhost:3000/callback"]', '["read", "write"]', 
			'["authorization_code"]', '["code"]', 0, 1
		)
	`)
	assert.NoError(t, err)
}

func TestGetOAuth2AuthorizationCodesSchema(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create required tables first
	_, err := db.Exec(GetOAuth2ClientsSchema())
	require.NoError(t, err)
	
	_, err = db.Exec(GetOAuth2AuthorizationCodesSchema())
	assert.NoError(t, err)
	
	// Verify table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth2_authorization_codes'").Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "oauth2_authorization_codes", tableName)
	
	// Test inserting a record with foreign key constraints
	_, err = db.Exec(`
		INSERT INTO users (id, username, email, password_hash) 
		VALUES ('user-1', 'testuser', 'test@example.com', 'hash')
	`)
	require.NoError(t, err)
	
	_, err = db.Exec(`
		INSERT INTO oauth2_clients (
			id, user_id, client_id, client_secret_hash, name,
			redirect_uris, scopes, grant_types, response_types
		) VALUES (
			'client-1', 'user-1', 'test_client_id', 'secret_hash', 'Test Client',
			'["http://localhost:3000/callback"]', '["read", "write"]', 
			'["authorization_code"]', '["code"]'
		)
	`)
	require.NoError(t, err)
	
	_, err = db.Exec(`
		INSERT INTO oauth2_authorization_codes (
			id, code_hash, client_id, user_id, redirect_uri, scopes, state,
			code_challenge, code_challenge_method, expires_at
		) VALUES (
			'auth-code-1', 'code_hash', 'test_client_id', 'user-1',
			'http://localhost:3000/callback', '["read"]', 'state123',
			'challenge', 'S256', datetime('now', '+10 minutes')
		)
	`)
	assert.NoError(t, err)
}

func TestGetOAuth2AccessTokensSchema(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create required tables first
	_, err := db.Exec(GetOAuth2ClientsSchema())
	require.NoError(t, err)
	
	_, err = db.Exec(GetOAuth2AccessTokensSchema())
	assert.NoError(t, err)
	
	// Verify table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth2_access_tokens'").Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "oauth2_access_tokens", tableName)
}

func TestGetOAuth2RefreshTokensSchema(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create required tables first
	_, err := db.Exec(GetOAuth2ClientsSchema())
	require.NoError(t, err)
	
	_, err = db.Exec(GetOAuth2AccessTokensSchema())
	require.NoError(t, err)
	
	_, err = db.Exec(GetOAuth2RefreshTokensSchema())
	assert.NoError(t, err)
	
	// Verify table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth2_refresh_tokens'").Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "oauth2_refresh_tokens", tableName)
}

func TestGetOAuth2Indexes(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	// Create all tables first
	schemas := []string{
		GetOAuth2ClientsSchema(),
		GetOAuth2AuthorizationCodesSchema(),
		GetOAuth2AccessTokensSchema(),
		GetOAuth2RefreshTokensSchema(),
	}
	
	for _, schema := range schemas {
		_, err := db.Exec(schema)
		require.NoError(t, err)
	}
	
	// Create all indexes
	indexes := GetOAuth2Indexes()
	for _, indexSQL := range indexes {
		_, err := db.Exec(indexSQL)
		assert.NoError(t, err, "Failed to create index: %s", indexSQL)
	}
	
	// Verify some key indexes exist
	keyIndexes := []string{
		"idx_oauth2_clients_client_id",
		"idx_oauth2_auth_codes_code_hash",
		"idx_oauth2_access_tokens_token_hash",
		"idx_oauth2_refresh_tokens_token_hash",
	}
	
	for _, indexName := range keyIndexes {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", indexName).Scan(&name)
		assert.NoError(t, err, "Index %s should exist", indexName)
		assert.Equal(t, indexName, name)
	}
}

func TestApplyAllOAuth2Migrations(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	ctx := context.Background()
	
	// Apply all OAuth2 migrations
	err := ApplyAllOAuth2Migrations(ctx, db)
	assert.NoError(t, err)
	
	// Verify all tables exist
	tables := []string{
		"oauth2_clients",
		"oauth2_authorization_codes",
		"oauth2_access_tokens",
		"oauth2_refresh_tokens",
	}
	
	for _, tableName := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&name)
		assert.NoError(t, err, "Table %s should exist", tableName)
		assert.Equal(t, tableName, name)
	}
	
	// Test that migrations are idempotent
	err = ApplyAllOAuth2Migrations(ctx, db)
	assert.NoError(t, err, "Applying migrations again should not fail")
}

func TestValidateOAuth2Schema(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	ctx := context.Background()
	
	// Schema validation should fail before migration
	err := ValidateOAuth2Schema(ctx, db)
	assert.Error(t, err)
	
	// Apply migrations
	err = ApplyAllOAuth2Migrations(ctx, db)
	require.NoError(t, err)
	
	// Schema validation should pass after migration
	err = ValidateOAuth2Schema(ctx, db)
	assert.NoError(t, err)
}

func TestGetOAuth2TableStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	
	ctx := context.Background()
	
	// Apply migrations
	err := ApplyAllOAuth2Migrations(ctx, db)
	require.NoError(t, err)
	
	// Get initial stats (should be all zeros)
	stats, err := GetOAuth2TableStats(ctx, db)
	assert.NoError(t, err)
	assert.Equal(t, 0, stats["oauth2_clients"])
	assert.Equal(t, 0, stats["oauth2_authorization_codes"])
	assert.Equal(t, 0, stats["oauth2_access_tokens"])
	assert.Equal(t, 0, stats["oauth2_refresh_tokens"])
	
	// Insert test data and verify stats update
	_, err = db.Exec(`
		INSERT INTO users (id, username, email, password_hash) 
		VALUES ('user-1', 'testuser', 'test@example.com', 'hash')
	`)
	require.NoError(t, err)
	
	_, err = db.Exec(`
		INSERT INTO oauth2_clients (
			id, user_id, client_id, client_secret_hash, name,
			redirect_uris, scopes, grant_types, response_types
		) VALUES (
			'client-1', 'user-1', 'test_client_id', 'secret_hash', 'Test Client',
			'["http://localhost:3000/callback"]', '["read", "write"]', 
			'["authorization_code"]', '["code"]'
		)
	`)
	require.NoError(t, err)
	
	stats, err = GetOAuth2TableStats(ctx, db)
	assert.NoError(t, err)
	assert.Equal(t, 1, stats["oauth2_clients"])
}

func TestOAuth2SchemaMigrationVersions(t *testing.T) {
	migrations := GetOAuth2Migrations()
	
	// Test that we have the expected number of migrations
	assert.Len(t, migrations, 5)
	
	// Test migration versions are in order
	expectedVersions := []string{
		"5",
		"6", 
		"7",
		"8",
		"9",
	}
	
	for i, migration := range migrations {
		assert.Equal(t, expectedVersions[i], migration.Version)
		assert.NotEmpty(t, migration.Name)
		assert.NotEmpty(t, migration.UpSQL)
		assert.NotEmpty(t, migration.DownSQL)
	}
}