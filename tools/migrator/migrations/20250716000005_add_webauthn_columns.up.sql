-- Add missing webauthn_credentials columns
-- Created: 2025-07-16
-- This migration adds the missing columns to webauthn_credentials table

ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS sign_count integer DEFAULT 0 NOT NULL;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS clone_warning boolean DEFAULT false NOT NULL;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS last_used_at timestamp with time zone;