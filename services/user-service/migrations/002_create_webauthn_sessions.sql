-- Migration: Create WebAuthn sessions table
-- Version: 002_create_webauthn_sessions
-- Description: Creates the webauthn_sessions table to store temporary session data for WebAuthn ceremonies

-- +migrate Up
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
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id ON webauthn_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_created_at ON webauthn_sessions(created_at);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_user_id_expires_at ON webauthn_sessions(user_id, expires_at);

-- Add comments for documentation
COMMENT ON TABLE webauthn_sessions IS 'Stores temporary session data for WebAuthn authentication ceremonies';
COMMENT ON COLUMN webauthn_sessions.id IS 'Unique identifier for the session';
COMMENT ON COLUMN webauthn_sessions.user_id IS 'Reference to the user for this session';
COMMENT ON COLUMN webauthn_sessions.challenge IS 'Random challenge bytes for this session';
COMMENT ON COLUMN webauthn_sessions.allowed_credential_ids IS 'JSON array of allowed credential IDs for this session';
COMMENT ON COLUMN webauthn_sessions.user_verification IS 'User verification requirement for this session';
COMMENT ON COLUMN webauthn_sessions.expires_at IS 'When this session expires';

-- +migrate Down
DROP INDEX IF EXISTS idx_webauthn_sessions_user_id_expires_at;
DROP INDEX IF EXISTS idx_webauthn_sessions_created_at;
DROP INDEX IF EXISTS idx_webauthn_sessions_expires_at;
DROP INDEX IF EXISTS idx_webauthn_sessions_user_id;
DROP TABLE IF EXISTS webauthn_sessions;