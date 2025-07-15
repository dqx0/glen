-- Add missing webauthn_credentials columns
-- Created: 2025-07-16
-- This migration adds the missing columns to webauthn_credentials table

ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS sign_count integer DEFAULT 0 NOT NULL;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS clone_warning boolean DEFAULT false NOT NULL;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS last_used_at timestamp with time zone;

-- Update existing credentials to have proper default values
UPDATE webauthn_credentials SET sign_count = 0 WHERE sign_count IS NULL;
UPDATE webauthn_credentials SET clone_warning = false WHERE clone_warning IS NULL;
UPDATE webauthn_credentials SET name = 'Default Credential' WHERE name IS NULL OR name = '';