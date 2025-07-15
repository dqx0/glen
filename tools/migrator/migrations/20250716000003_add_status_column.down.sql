-- Remove status column from users table
-- Created: 2025-07-16
-- This migration removes the status column

ALTER TABLE users DROP COLUMN IF EXISTS status;