-- Add status column to users table
-- Created: 2025-07-16
-- This migration adds the missing status column

ALTER TABLE users ADD COLUMN IF NOT EXISTS status character varying(20) DEFAULT 'active'::character varying NOT NULL;

-- Update existing users to have 'active' status
UPDATE users SET status = 'active' WHERE status IS NULL OR status = '';