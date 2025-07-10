-- Migration: Create WebAuthn credentials table
-- Version: 001_create_webauthn_credentials
-- Description: Creates the webauthn_credentials table to store user WebAuthn credentials

-- +migrate Up
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_webauthn_credentials_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_created_at ON webauthn_credentials(created_at);

-- Add comments for documentation
COMMENT ON TABLE webauthn_credentials IS 'Stores WebAuthn credentials for users';
COMMENT ON COLUMN webauthn_credentials.id IS 'Unique identifier for the credential record';
COMMENT ON COLUMN webauthn_credentials.user_id IS 'Reference to the user who owns this credential';
COMMENT ON COLUMN webauthn_credentials.credential_id IS 'Unique credential ID from the authenticator';
COMMENT ON COLUMN webauthn_credentials.public_key IS 'The public key associated with this credential';
COMMENT ON COLUMN webauthn_credentials.attestation_type IS 'Type of attestation used during registration';
COMMENT ON COLUMN webauthn_credentials.transport IS 'Comma-separated list of supported transports';
COMMENT ON COLUMN webauthn_credentials.user_present IS 'Flag indicating if user presence was verified';
COMMENT ON COLUMN webauthn_credentials.user_verified IS 'Flag indicating if user verification was performed';
COMMENT ON COLUMN webauthn_credentials.backup_eligible IS 'Flag indicating if credential is backup eligible';
COMMENT ON COLUMN webauthn_credentials.backup_state IS 'Flag indicating current backup state';
COMMENT ON COLUMN webauthn_credentials.sign_count IS 'Counter for preventing replay attacks';
COMMENT ON COLUMN webauthn_credentials.clone_warning IS 'Flag indicating potential credential cloning';

-- +migrate Down
DROP INDEX IF EXISTS idx_webauthn_credentials_created_at;
DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;
DROP INDEX IF EXISTS idx_webauthn_credentials_user_id;
DROP TABLE IF EXISTS webauthn_credentials;