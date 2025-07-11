package database

// GetWebAuthnCredentialsSchemaPostgreSQL returns the PostgreSQL-specific SQL for creating the webauthn_credentials table
func GetWebAuthnCredentialsSchemaPostgreSQL() string {
	return `
		CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			credential_id BYTEA NOT NULL UNIQUE,
			public_key BYTEA NOT NULL,
			attestation_type VARCHAR(50) DEFAULT 'none',
			transport VARCHAR(255) DEFAULT '',
			user_present BOOLEAN NOT NULL DEFAULT FALSE,
			user_verified BOOLEAN NOT NULL DEFAULT FALSE,
			backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
			backup_state BOOLEAN NOT NULL DEFAULT FALSE,
			sign_count INTEGER NOT NULL DEFAULT 0,
			clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
			name VARCHAR(255) NOT NULL DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			CONSTRAINT fk_webauthn_credentials_user_id 
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`
}

// GetWebAuthnSessionsSchemaPostgreSQL returns the PostgreSQL-specific SQL for creating the webauthn_sessions table
func GetWebAuthnSessionsSchemaPostgreSQL() string {
	return `
		CREATE TABLE IF NOT EXISTS webauthn_sessions (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			challenge BYTEA NOT NULL,
			allowed_credential_ids TEXT DEFAULT '',
			user_verification VARCHAR(50) DEFAULT 'preferred',
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			CONSTRAINT fk_webauthn_sessions_user_id 
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`
}

// GetWebAuthnIndexesPostgreSQL returns the PostgreSQL-specific SQL statements for creating WebAuthn-related indexes
func GetWebAuthnIndexesPostgreSQL() []string {
	return []string{
		// Indexes for webauthn_credentials table
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_created_at ON webauthn_credentials(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_updated_at ON webauthn_credentials(updated_at)",
		
		// Indexes for webauthn_sessions table
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_created_at ON webauthn_sessions(created_at)",
		
		// Composite indexes for common queries
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id_created_at ON webauthn_credentials(user_id, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id_expires_at ON webauthn_sessions(user_id, expires_at)",
	}
}

// GetWebAuthnMigrationsPostgreSQL returns all PostgreSQL-specific WebAuthn migrations
func GetWebAuthnMigrationsPostgreSQL() []Migration {
	return []Migration{
		{
			Version: "001_create_webauthn_credentials_pg",
			Name:    "Create WebAuthn credentials table (PostgreSQL)",
			UpSQL:   GetWebAuthnCredentialsSchemaPostgreSQL(),
			DownSQL: "DROP TABLE IF EXISTS webauthn_credentials CASCADE",
		},
		{
			Version: "002_create_webauthn_sessions_pg",
			Name:    "Create WebAuthn sessions table (PostgreSQL)",
			UpSQL:   GetWebAuthnSessionsSchemaPostgreSQL(),
			DownSQL: "DROP TABLE IF EXISTS webauthn_sessions CASCADE",
		},
		{
			Version: "003_create_webauthn_indexes_pg",
			Name:    "Create WebAuthn indexes (PostgreSQL)",
			UpSQL:   createIndexesSQLPostgreSQL(),
			DownSQL: dropIndexesSQLPostgreSQL(),
		},
		{
			Version: "004_add_webauthn_triggers_pg",
			Name:    "Add WebAuthn triggers (PostgreSQL)",
			UpSQL:   getWebAuthnTriggersPostgreSQL(),
			DownSQL: dropWebAuthnTriggersPostgreSQL(),
		},
	}
}

// createIndexesSQLPostgreSQL combines all PostgreSQL index creation statements
func createIndexesSQLPostgreSQL() string {
	indexes := GetWebAuthnIndexesPostgreSQL()
	sql := ""
	for _, index := range indexes {
		sql += index + ";\n"
	}
	return sql
}

// dropIndexesSQLPostgreSQL creates SQL to drop all WebAuthn indexes in PostgreSQL
func dropIndexesSQLPostgreSQL() string {
	return `
		DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
		DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;
		DROP INDEX IF EXISTS idx_webauthn_credentials_created_at;
		DROP INDEX IF EXISTS idx_webauthn_credentials_updated_at;
		DROP INDEX IF EXISTS idx_webauthn_sessions_user_id;
		DROP INDEX IF EXISTS idx_webauthn_sessions_expires_at;
		DROP INDEX IF EXISTS idx_webauthn_sessions_created_at;
		DROP INDEX IF EXISTS idx_webauthn_credentials_user_id_created_at;
		DROP INDEX IF EXISTS idx_webauthn_sessions_user_id_expires_at;
	`
}

// getWebAuthnTriggersPostgreSQL returns SQL for creating PostgreSQL triggers
func getWebAuthnTriggersPostgreSQL() string {
	return `
		-- Function to update updated_at timestamp
		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = NOW();
			RETURN NEW;
		END;
		$$ language 'plpgsql';

		-- Trigger for webauthn_credentials table
		CREATE TRIGGER update_webauthn_credentials_updated_at 
			BEFORE UPDATE ON webauthn_credentials 
			FOR EACH ROW 
			EXECUTE FUNCTION update_updated_at_column();

		-- Function to clean up expired sessions
		CREATE OR REPLACE FUNCTION cleanup_expired_webauthn_sessions()
		RETURNS void AS $$
		BEGIN
			DELETE FROM webauthn_sessions WHERE expires_at < NOW();
		END;
		$$ language 'plpgsql';
	`
}

// dropWebAuthnTriggersPostgreSQL returns SQL for dropping PostgreSQL triggers
func dropWebAuthnTriggersPostgreSQL() string {
	return `
		DROP TRIGGER IF EXISTS update_webauthn_credentials_updated_at ON webauthn_credentials;
		DROP FUNCTION IF EXISTS update_updated_at_column();
		DROP FUNCTION IF EXISTS cleanup_expired_webauthn_sessions();
	`
}

// GetPostgreSQLSchemaValidationSQL returns SQL queries to validate PostgreSQL schema
func GetPostgreSQLSchemaValidationSQL() map[string]string {
	return map[string]string{
		"check_webauthn_credentials_table": `
			SELECT COUNT(*) FROM information_schema.tables 
			WHERE table_name = 'webauthn_credentials' AND table_schema = 'public'
		`,
		"check_webauthn_sessions_table": `
			SELECT COUNT(*) FROM information_schema.tables 
			WHERE table_name = 'webauthn_sessions' AND table_schema = 'public'
		`,
		"check_webauthn_credentials_columns": `
			SELECT column_name FROM information_schema.columns 
			WHERE table_name = 'webauthn_credentials' AND table_schema = 'public'
			ORDER BY ordinal_position
		`,
		"check_webauthn_sessions_columns": `
			SELECT column_name FROM information_schema.columns 
			WHERE table_name = 'webauthn_sessions' AND table_schema = 'public'
			ORDER BY ordinal_position
		`,
		"check_foreign_key_constraints": `
			SELECT constraint_name, table_name, column_name, foreign_table_name, foreign_column_name
			FROM information_schema.key_column_usage kcu
			JOIN information_schema.referential_constraints rc ON kcu.constraint_name = rc.constraint_name
			JOIN information_schema.key_column_usage fkcu ON rc.unique_constraint_name = fkcu.constraint_name
			WHERE kcu.table_name IN ('webauthn_credentials', 'webauthn_sessions')
		`,
		"check_indexes": `
			SELECT indexname FROM pg_indexes 
			WHERE tablename IN ('webauthn_credentials', 'webauthn_sessions')
			AND schemaname = 'public'
		`,
	}
}