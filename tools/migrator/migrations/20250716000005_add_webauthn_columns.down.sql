-- Remove webauthn_credentials columns
-- Created: 2025-07-16
-- This migration removes the added columns from webauthn_credentials table

ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS name;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS clone_warning;
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS sign_count;