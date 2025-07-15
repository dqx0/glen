-- Add cors_dynamic_origins table
-- Created: 2025-07-16
-- This migration adds the missing cors_dynamic_origins table

CREATE TABLE IF NOT EXISTS cors_dynamic_origins (
    id SERIAL PRIMARY KEY,
    origin TEXT NOT NULL,
    oauth2_client_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    UNIQUE (origin, oauth2_client_id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_cors_dynamic_origins_origin ON cors_dynamic_origins(origin);
CREATE INDEX IF NOT EXISTS idx_cors_dynamic_origins_client_id ON cors_dynamic_origins(oauth2_client_id);