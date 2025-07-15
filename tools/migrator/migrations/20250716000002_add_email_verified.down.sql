-- Remove email_verified column from users table
-- Created: 2025-07-16
-- This migration removes the email_verified column

ALTER TABLE users DROP COLUMN IF EXISTS email_verified;