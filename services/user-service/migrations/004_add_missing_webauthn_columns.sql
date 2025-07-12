-- Migration: Add missing columns to WebAuthn credentials table
-- Version: 004_add_missing_webauthn_columns
-- Description: Adds missing last_used_at and name columns to webauthn_credentials table

-- +migrate Up

-- Add last_used_at column if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'webauthn_credentials' 
                   AND column_name = 'last_used_at') THEN
        ALTER TABLE webauthn_credentials ADD COLUMN last_used_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- Add name column if it doesn't exist (with better default)
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'webauthn_credentials' 
                   AND column_name = 'name') THEN
        ALTER TABLE webauthn_credentials ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT 'Security Key';
    END IF;
END $$;

-- Ensure counter column is renamed to sign_count if it exists
DO $$ 
BEGIN 
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'webauthn_credentials' 
               AND column_name = 'counter') 
    AND NOT EXISTS (SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'webauthn_credentials' 
                    AND column_name = 'sign_count') THEN
        ALTER TABLE webauthn_credentials RENAME COLUMN counter TO sign_count;
    END IF;
END $$;

-- Add flags column as JSONB if it doesn't exist
DO $$ 
BEGIN 
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'webauthn_credentials' 
                   AND column_name = 'flags') THEN
        ALTER TABLE webauthn_credentials ADD COLUMN flags JSONB DEFAULT '{"user_present": false, "user_verified": false, "backup_eligible": false, "backup_state": false}';
    END IF;
END $$;

-- Update existing rows with proper flag values
UPDATE webauthn_credentials 
SET flags = jsonb_build_object(
    'user_present', COALESCE(user_present, false),
    'user_verified', COALESCE(user_verified, false), 
    'backup_eligible', COALESCE(backup_eligible, false),
    'backup_state', COALESCE(backup_state, false)
)
WHERE flags IS NULL;

-- Add comments for new columns
COMMENT ON COLUMN webauthn_credentials.last_used_at IS 'Timestamp when this credential was last used for authentication';
COMMENT ON COLUMN webauthn_credentials.name IS 'User-assigned name for this credential';
COMMENT ON COLUMN webauthn_credentials.flags IS 'Authenticator flags as JSON object';

-- +migrate Down

-- Remove added columns (be careful with data loss)
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS flags;

-- Note: We don't rename sign_count back to counter or remove name column 
-- to avoid data loss and maintain compatibility