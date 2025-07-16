-- Add name column to schema_migrations table
-- Created: 2025-07-16

-- Check if the column exists before adding it
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'schema_migrations' 
        AND column_name = 'name'
    ) THEN
        ALTER TABLE schema_migrations ADD COLUMN name VARCHAR(255) DEFAULT '';
    END IF;
END
$$;