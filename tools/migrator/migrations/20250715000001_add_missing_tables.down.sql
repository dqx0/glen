-- Migration DOWN: initial_schema
-- This will remove all tables and structures created in the UP migration

-- Drop all triggers first
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_social_accounts_updated_at ON social_accounts;

-- Drop all foreign key constraints (automatically dropped with tables, but listing for clarity)
-- oauth2_refresh_tokens constraints
ALTER TABLE IF EXISTS oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_access_token_id_fkey;
ALTER TABLE IF EXISTS oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_client_id_fkey;
ALTER TABLE IF EXISTS oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_user_id_fkey;

-- oauth2_access_tokens constraints
ALTER TABLE IF EXISTS oauth2_access_tokens DROP CONSTRAINT IF EXISTS oauth2_access_tokens_client_id_fkey;
ALTER TABLE IF EXISTS oauth2_access_tokens DROP CONSTRAINT IF EXISTS oauth2_access_tokens_user_id_fkey;

-- oauth2_authorization_codes constraints
ALTER TABLE IF EXISTS oauth2_authorization_codes DROP CONSTRAINT IF EXISTS oauth2_authorization_codes_client_id_fkey;
ALTER TABLE IF EXISTS oauth2_authorization_codes DROP CONSTRAINT IF EXISTS oauth2_authorization_codes_user_id_fkey;

-- oauth2_clients constraints
ALTER TABLE IF EXISTS oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_user_id_fkey;

-- Drop all indexes
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_token_hash;
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_revoked_at;
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth2_refresh_tokens_access_token_id;

DROP INDEX IF EXISTS idx_oauth2_access_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth2_access_tokens_token_hash;
DROP INDEX IF EXISTS idx_oauth2_access_tokens_revoked_at;
DROP INDEX IF EXISTS idx_oauth2_access_tokens_expires_at;
DROP INDEX IF EXISTS idx_oauth2_access_tokens_client_id;

DROP INDEX IF EXISTS idx_oauth2_auth_codes_user_id;
DROP INDEX IF EXISTS idx_oauth2_auth_codes_used_at;
DROP INDEX IF EXISTS idx_oauth2_auth_codes_expires_at;
DROP INDEX IF EXISTS idx_oauth2_auth_codes_code_hash;
DROP INDEX IF EXISTS idx_oauth2_auth_codes_client_id;

DROP INDEX IF EXISTS idx_oauth2_clients_user_id;
DROP INDEX IF EXISTS idx_oauth2_clients_is_active;
DROP INDEX IF EXISTS idx_oauth2_clients_created_at;
DROP INDEX IF EXISTS idx_oauth2_clients_client_id;

DROP INDEX IF EXISTS idx_webauthn_sessions_user_id;
DROP INDEX IF EXISTS idx_webauthn_sessions_expires_at;
DROP INDEX IF EXISTS idx_webauthn_sessions_created_at;

DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
DROP INDEX IF EXISTS idx_webauthn_credentials_last_used_at;
DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;
DROP INDEX IF EXISTS idx_webauthn_credentials_created_at;

DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;

DROP INDEX IF EXISTS idx_social_accounts_user_id;
DROP INDEX IF EXISTS idx_social_accounts_provider;

DROP INDEX IF EXISTS idx_api_tokens_user_id;
DROP INDEX IF EXISTS idx_api_tokens_type;
DROP INDEX IF EXISTS idx_api_tokens_token_hash;

-- Drop all tables in reverse dependency order
DROP TABLE IF EXISTS oauth2_refresh_tokens;
DROP TABLE IF EXISTS oauth2_access_tokens;
DROP TABLE IF EXISTS oauth2_authorization_codes;
DROP TABLE IF EXISTS oauth2_clients;
DROP TABLE IF EXISTS webauthn_sessions;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS social_accounts;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS schema_migrations;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop extension (only if no other objects depend on it)
-- Note: Be careful with this in production as other applications might use UUID
DROP EXTENSION IF EXISTS "uuid-ossp";