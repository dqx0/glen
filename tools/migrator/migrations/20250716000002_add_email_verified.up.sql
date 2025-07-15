-- Add email_verified column to users table
-- Created: 2025-07-16
-- This migration adds the missing email_verified column

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean DEFAULT false NOT NULL;

-- Update existing users to have email_verified = false
UPDATE users SET email_verified = false WHERE email_verified IS NULL;