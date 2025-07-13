-- Migration: Create CORS dynamic origins table
-- Description: Store dynamic CORS origins associated with OAuth2 clients
-- Created: 2025-01-13

-- Create the cors_dynamic_origins table
CREATE TABLE IF NOT EXISTS cors_dynamic_origins (
    id SERIAL PRIMARY KEY,
    origin VARCHAR(255) NOT NULL,
    oauth2_client_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Ensure we don't have duplicate origin-client combinations
    UNIQUE(origin, oauth2_client_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_cors_origins_origin ON cors_dynamic_origins(origin);
CREATE INDEX IF NOT EXISTS idx_cors_origins_client_id ON cors_dynamic_origins(oauth2_client_id);
CREATE INDEX IF NOT EXISTS idx_cors_origins_created_at ON cors_dynamic_origins(created_at);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_cors_origins_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tr_cors_origins_updated_at
    BEFORE UPDATE ON cors_dynamic_origins
    FOR EACH ROW
    EXECUTE FUNCTION update_cors_origins_updated_at();

-- Add comments for documentation
COMMENT ON TABLE cors_dynamic_origins IS 'Dynamic CORS origins associated with OAuth2 clients';
COMMENT ON COLUMN cors_dynamic_origins.id IS 'Primary key';
COMMENT ON COLUMN cors_dynamic_origins.origin IS 'CORS origin (e.g., https://example.com)';
COMMENT ON COLUMN cors_dynamic_origins.oauth2_client_id IS 'Associated OAuth2 client ID';
COMMENT ON COLUMN cors_dynamic_origins.created_at IS 'When the origin was first added';
COMMENT ON COLUMN cors_dynamic_origins.updated_at IS 'When the origin was last updated';

-- Create a view for easy monitoring
CREATE OR REPLACE VIEW cors_origins_summary AS
SELECT 
    origin,
    COUNT(*) as client_count,
    ARRAY_AGG(oauth2_client_id ORDER BY oauth2_client_id) as client_ids,
    MIN(created_at) as first_added,
    MAX(updated_at) as last_updated
FROM cors_dynamic_origins
GROUP BY origin
ORDER BY client_count DESC, origin;

COMMENT ON VIEW cors_origins_summary IS 'Summary view of CORS origins and their associated clients';