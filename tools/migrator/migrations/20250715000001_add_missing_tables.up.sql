-- Add missing tables from initial schema
-- Created: 2025-07-15

-- Users table (if not exists)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Social accounts table (if not exists)
CREATE TABLE IF NOT EXISTS social_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_id TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    profile_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_id)
);

-- API tokens table (if not exists)
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- OAuth2 clients table (if not exists)
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    redirect_uris TEXT NOT NULL,
    scopes TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic',
    is_public BOOLEAN DEFAULT FALSE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- OAuth2 authorization codes table (if not exists)
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    state TEXT DEFAULT '',
    code_challenge TEXT DEFAULT '',
    code_challenge_method TEXT DEFAULT '',
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    used_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- OAuth2 access tokens table (if not exists)
CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    token_type TEXT DEFAULT 'Bearer',
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- OAuth2 refresh tokens table (if not exists)
CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    access_token_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITHOUT TIME ZONE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes if they don't exist
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_social_accounts_user_id ON social_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_social_accounts_provider ON social_accounts(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_type ON api_tokens(token_type);

-- OAuth2 indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_user_id ON oauth2_clients(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_client_id ON oauth2_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_is_active ON oauth2_clients(is_active);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_created_at ON oauth2_clients(created_at);

CREATE INDEX IF NOT EXISTS idx_oauth2_auth_codes_code_hash ON oauth2_authorization_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_codes_client_id ON oauth2_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_codes_user_id ON oauth2_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_codes_expires_at ON oauth2_authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_codes_used_at ON oauth2_authorization_codes(used_at);

CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_token_hash ON oauth2_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_client_id ON oauth2_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_user_id ON oauth2_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_expires_at ON oauth2_access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_revoked_at ON oauth2_access_tokens(revoked_at);

CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_token_hash ON oauth2_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_access_token_id ON oauth2_refresh_tokens(access_token_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_client_id ON oauth2_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_user_id ON oauth2_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_expires_at ON oauth2_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_tokens_revoked_at ON oauth2_refresh_tokens(revoked_at);

-- Create update trigger function if not exists
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers if they don't exist
DO $$ BEGIN
    CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER update_social_accounts_updated_at BEFORE UPDATE ON social_accounts
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Add foreign key constraints if they don't exist
DO $$ BEGIN
    ALTER TABLE webauthn_credentials ADD CONSTRAINT webauthn_credentials_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE webauthn_sessions ADD CONSTRAINT webauthn_sessions_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE social_accounts ADD CONSTRAINT social_accounts_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_clients ADD CONSTRAINT oauth2_clients_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_authorization_codes ADD CONSTRAINT oauth2_authorization_codes_client_id_fkey 
        FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_authorization_codes ADD CONSTRAINT oauth2_authorization_codes_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_access_tokens ADD CONSTRAINT oauth2_access_tokens_client_id_fkey 
        FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_access_tokens ADD CONSTRAINT oauth2_access_tokens_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_refresh_tokens ADD CONSTRAINT oauth2_refresh_tokens_access_token_id_fkey 
        FOREIGN KEY (access_token_id) REFERENCES oauth2_access_tokens(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_refresh_tokens ADD CONSTRAINT oauth2_refresh_tokens_client_id_fkey 
        FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE oauth2_refresh_tokens ADD CONSTRAINT oauth2_refresh_tokens_user_id_fkey 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
