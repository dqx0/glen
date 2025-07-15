-- Drop full schema
-- Created: 2025-07-16
-- This migration drops all tables and functions

-- Drop foreign key constraints first
ALTER TABLE IF EXISTS public.api_tokens DROP CONSTRAINT IF EXISTS api_tokens_user_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_access_tokens DROP CONSTRAINT IF EXISTS oauth2_access_tokens_client_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_access_tokens DROP CONSTRAINT IF EXISTS oauth2_access_tokens_user_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_authorization_codes DROP CONSTRAINT IF EXISTS oauth2_authorization_codes_client_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_authorization_codes DROP CONSTRAINT IF EXISTS oauth2_authorization_codes_user_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_clients DROP CONSTRAINT IF EXISTS oauth2_clients_user_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_access_token_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_client_id_fkey;
ALTER TABLE IF EXISTS public.oauth2_refresh_tokens DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_user_id_fkey;
ALTER TABLE IF EXISTS public.social_accounts DROP CONSTRAINT IF EXISTS social_accounts_user_id_fkey;
ALTER TABLE IF EXISTS public.webauthn_credentials DROP CONSTRAINT IF EXISTS webauthn_credentials_user_id_fkey;
ALTER TABLE IF EXISTS public.webauthn_sessions DROP CONSTRAINT IF EXISTS webauthn_sessions_user_id_fkey;

-- Drop all tables
DROP TABLE IF EXISTS public.webauthn_sessions CASCADE;
DROP TABLE IF EXISTS public.webauthn_credentials CASCADE;
DROP TABLE IF EXISTS public.oauth2_refresh_tokens CASCADE;
DROP TABLE IF EXISTS public.oauth2_access_tokens CASCADE;
DROP TABLE IF EXISTS public.oauth2_authorization_codes CASCADE;
DROP TABLE IF EXISTS public.oauth2_clients CASCADE;
DROP TABLE IF EXISTS public.social_accounts CASCADE;
DROP TABLE IF EXISTS public.api_tokens CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.schema_migrations CASCADE;

-- Drop functions
DROP FUNCTION IF EXISTS public.update_updated_at_column() CASCADE;

-- Drop extension (if no other objects depend on it)
-- DROP EXTENSION IF EXISTS "uuid-ossp" CASCADE;