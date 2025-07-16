-- Fix webauthn_credentials table schema to match implementation
-- Created: 2025-07-16
-- This migration removes the authenticator column and adds individual flag columns

-- First, add the individual flag columns
ALTER TABLE webauthn_credentials 
ADD COLUMN IF NOT EXISTS user_present boolean NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS user_verified boolean NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS backup_eligible boolean NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS backup_state boolean NOT NULL DEFAULT false;

-- Drop the authenticator column that's not used in the implementation
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS authenticator;

-- Drop the flags column that's not used in the implementation
-- Note: Must drop flags column constraints first if they exist
ALTER TABLE webauthn_credentials DROP COLUMN IF EXISTS flags CASCADE;

-- Update the transport column to be compatible with the working implementation
-- (This should already be text[] from previous migrations but let's ensure it)
-- The transport column should stay as text[] for PostgreSQL arrays