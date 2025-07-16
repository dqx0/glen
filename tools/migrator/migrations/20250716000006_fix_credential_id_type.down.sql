-- Rollback credential_id column type from BYTEA to TEXT
-- Created: 2025-07-16
-- This migration rolls back the credential_id column to TEXT type

-- First, drop the existing unique constraint and index
ALTER TABLE webauthn_credentials DROP CONSTRAINT IF EXISTS webauthn_credentials_credential_id_key;
DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;

-- Change the column type from BYTEA to TEXT
ALTER TABLE webauthn_credentials ALTER COLUMN credential_id TYPE TEXT USING credential_id::text;

-- Recreate the unique constraint and index
ALTER TABLE webauthn_credentials ADD CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id);
CREATE INDEX idx_webauthn_credentials_credential_id ON webauthn_credentials USING btree (credential_id);