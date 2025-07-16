-- Remove name column from schema_migrations table
-- Created: 2025-07-16

ALTER TABLE schema_migrations DROP COLUMN IF EXISTS name;