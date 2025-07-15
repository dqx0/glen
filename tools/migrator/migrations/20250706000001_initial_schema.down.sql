-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_social_accounts_updated_at ON social_accounts;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_api_tokens_type;
DROP INDEX IF EXISTS idx_api_tokens_token_hash;
DROP INDEX IF EXISTS idx_api_tokens_user_id;
DROP INDEX IF EXISTS idx_social_accounts_provider;
DROP INDEX IF EXISTS idx_social_accounts_user_id;
DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;
DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_username;

-- Drop tables
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS social_accounts;
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS users;

-- Drop extension
DROP EXTENSION IF EXISTS "uuid-ossp";