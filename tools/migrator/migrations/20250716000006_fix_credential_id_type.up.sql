-- Fix credential_id column type from TEXT to BYTEA
-- Created: 2025-07-16
-- This migration changes the credential_id column to properly store binary data

-- First, drop the existing unique constraint and index
ALTER TABLE webauthn_credentials DROP CONSTRAINT IF EXISTS webauthn_credentials_credential_id_key;
DROP INDEX IF EXISTS idx_webauthn_credentials_credential_id;

-- Change the column type from TEXT to BYTEA
ALTER TABLE webauthn_credentials ALTER COLUMN credential_id TYPE BYTEA USING credential_id::bytea;

-- Recreate the unique constraint and index
ALTER TABLE webauthn_credentials ADD CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id);
CREATE INDEX idx_webauthn_credentials_credential_id ON webauthn_credentials USING btree (credential_id);