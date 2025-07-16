-- Rollback webauthn_credentials table schema changes
-- Created: 2025-07-16
-- This migration adds back the authenticator column and removes individual flag columns

-- Add back the authenticator column
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS authenticator jsonb NOT NULL DEFAULT '{}';

-- Add back the flags column
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS flags jsonb NOT NULL DEFAULT '{}';

-- Remove the individual flag columns
ALTER TABLE webauthn_credentials 
DROP COLUMN IF EXISTS user_present,
DROP COLUMN IF EXISTS user_verified,
DROP COLUMN IF EXISTS backup_eligible,
DROP COLUMN IF EXISTS backup_state;