-- Migration: Add WebAuthn triggers and functions
-- Version: 003_add_webauthn_triggers
-- Description: Adds triggers and functions for WebAuthn table maintenance

-- +migrate Up

-- Function to update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update updated_at on webauthn_credentials
CREATE TRIGGER update_webauthn_credentials_updated_at 
    BEFORE UPDATE ON webauthn_credentials 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired WebAuthn sessions
CREATE OR REPLACE FUNCTION cleanup_expired_webauthn_sessions()
RETURNS void AS $$
BEGIN
    DELETE FROM webauthn_sessions WHERE expires_at < NOW();
    -- Log the cleanup operation
    RAISE NOTICE 'Cleaned up expired WebAuthn sessions at %', NOW();
END;
$$ language 'plpgsql';

-- Function to validate WebAuthn credential data
CREATE OR REPLACE FUNCTION validate_webauthn_credential()
RETURNS TRIGGER AS $$
BEGIN
    -- Validate credential_id is not empty
    IF length(NEW.credential_id) = 0 THEN
        RAISE EXCEPTION 'credential_id cannot be empty';
    END IF;
    
    -- Validate public_key is not empty
    IF length(NEW.public_key) = 0 THEN
        RAISE EXCEPTION 'public_key cannot be empty';
    END IF;
    
    -- Validate sign_count is not negative
    IF NEW.sign_count < 0 THEN
        RAISE EXCEPTION 'sign_count cannot be negative';
    END IF;
    
    -- Validate attestation_type is a known value
    IF NEW.attestation_type NOT IN ('none', 'indirect', 'direct') THEN
        RAISE EXCEPTION 'attestation_type must be none, indirect, or direct';
    END IF;
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to validate WebAuthn credential data before insert or update
CREATE TRIGGER validate_webauthn_credential_trigger
    BEFORE INSERT OR UPDATE ON webauthn_credentials
    FOR EACH ROW
    EXECUTE FUNCTION validate_webauthn_credential();

-- Function to validate WebAuthn session data
CREATE OR REPLACE FUNCTION validate_webauthn_session()
RETURNS TRIGGER AS $$
BEGIN
    -- Validate challenge is not empty
    IF length(NEW.challenge) = 0 THEN
        RAISE EXCEPTION 'challenge cannot be empty';
    END IF;
    
    -- Validate challenge is at least 32 bytes
    IF length(NEW.challenge) < 32 THEN
        RAISE EXCEPTION 'challenge must be at least 32 bytes';
    END IF;
    
    -- Validate expires_at is in the future
    IF NEW.expires_at <= NOW() THEN
        RAISE EXCEPTION 'expires_at must be in the future';
    END IF;
    
    -- Validate user_verification is a known value
    IF NEW.user_verification NOT IN ('required', 'preferred', 'discouraged') THEN
        RAISE EXCEPTION 'user_verification must be required, preferred, or discouraged';
    END IF;
    
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to validate WebAuthn session data before insert or update
CREATE TRIGGER validate_webauthn_session_trigger
    BEFORE INSERT OR UPDATE ON webauthn_sessions
    FOR EACH ROW
    EXECUTE FUNCTION validate_webauthn_session();

-- Function to log WebAuthn credential operations for security auditing
CREATE OR REPLACE FUNCTION log_webauthn_credential_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RAISE NOTICE 'WebAuthn credential created: user_id=%, credential_id=%, at=%', 
            NEW.user_id, encode(NEW.credential_id, 'hex'), NEW.created_at;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Log if sign_count changed (potential security event)
        IF OLD.sign_count != NEW.sign_count THEN
            RAISE NOTICE 'WebAuthn credential sign_count changed: user_id=%, credential_id=%, old_count=%, new_count=%, at=%',
                NEW.user_id, encode(NEW.credential_id, 'hex'), OLD.sign_count, NEW.sign_count, NOW();
        END IF;
        -- Log if clone_warning flag changed
        IF OLD.clone_warning != NEW.clone_warning THEN
            RAISE NOTICE 'WebAuthn credential clone_warning changed: user_id=%, credential_id=%, warning=%, at=%',
                NEW.user_id, encode(NEW.credential_id, 'hex'), NEW.clone_warning, NOW();
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        RAISE NOTICE 'WebAuthn credential deleted: user_id=%, credential_id=%, at=%',
            OLD.user_id, encode(OLD.credential_id, 'hex'), NOW();
    END IF;
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ language 'plpgsql';

-- Trigger to log WebAuthn credential operations
CREATE TRIGGER log_webauthn_credential_changes_trigger
    AFTER INSERT OR UPDATE OR DELETE ON webauthn_credentials
    FOR EACH ROW
    EXECUTE FUNCTION log_webauthn_credential_changes();

-- Add additional indexes for better performance on common queries
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_updated_at ON webauthn_credentials(updated_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_sign_count ON webauthn_credentials(sign_count);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_clone_warning ON webauthn_credentials(clone_warning) WHERE clone_warning = true;

-- Partial index for active (non-expired) sessions
CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_active ON webauthn_sessions(user_id, created_at) WHERE expires_at > NOW();

-- +migrate Down

-- Drop indexes
DROP INDEX IF EXISTS idx_webauthn_sessions_active;
DROP INDEX IF EXISTS idx_webauthn_credentials_clone_warning;
DROP INDEX IF EXISTS idx_webauthn_credentials_sign_count;
DROP INDEX IF EXISTS idx_webauthn_credentials_updated_at;

-- Drop triggers
DROP TRIGGER IF EXISTS log_webauthn_credential_changes_trigger ON webauthn_credentials;
DROP TRIGGER IF EXISTS validate_webauthn_session_trigger ON webauthn_sessions;
DROP TRIGGER IF EXISTS validate_webauthn_credential_trigger ON webauthn_credentials;
DROP TRIGGER IF EXISTS update_webauthn_credentials_updated_at ON webauthn_credentials;

-- Drop functions
DROP FUNCTION IF EXISTS log_webauthn_credential_changes();
DROP FUNCTION IF EXISTS validate_webauthn_session();
DROP FUNCTION IF EXISTS validate_webauthn_credential();
DROP FUNCTION IF EXISTS cleanup_expired_webauthn_sessions();
DROP FUNCTION IF EXISTS update_updated_at_column();