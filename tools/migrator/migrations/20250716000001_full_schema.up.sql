-- Full schema migration from glen_db.txt
-- Created: 2025-07-16
-- This migration creates the complete database schema from zero

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: glen_dev
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

SET default_tablespace = '';
SET default_table_access_method = heap;

--
-- Name: api_tokens; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.api_tokens (
    id text NOT NULL,
    user_id text NOT NULL,
    token_type character varying(20) NOT NULL,
    token_hash text NOT NULL,
    name text NOT NULL,
    scopes text[],
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone
);

--
-- Name: oauth2_access_tokens; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.oauth2_access_tokens (
    id text NOT NULL,
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text NOT NULL,
    token_type text DEFAULT 'Bearer'::text,
    expires_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

--
-- Name: oauth2_authorization_codes; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.oauth2_authorization_codes (
    id text NOT NULL,
    code_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    redirect_uri text NOT NULL,
    scopes text NOT NULL,
    state text DEFAULT ''::text,
    code_challenge text DEFAULT ''::text,
    code_challenge_method text DEFAULT ''::text,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

--
-- Name: oauth2_clients; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.oauth2_clients (
    id text NOT NULL,
    user_id text NOT NULL,
    client_id text NOT NULL,
    client_secret_hash text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    redirect_uris text NOT NULL,
    scopes text NOT NULL,
    grant_types text NOT NULL,
    response_types text NOT NULL,
    token_endpoint_auth_method text DEFAULT 'client_secret_basic'::text,
    is_public boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

--
-- Name: oauth2_refresh_tokens; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.oauth2_refresh_tokens (
    id text NOT NULL,
    token_hash text NOT NULL,
    access_token_id text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: glen_dev
-- Note: This table is managed by the migration tool itself, so we don't create it
--

-- CREATE TABLE public.schema_migrations (
--     version character varying(255) NOT NULL,
--     dirty boolean DEFAULT false NOT NULL,
--     applied_at timestamp with time zone DEFAULT now()
-- );

--
-- Name: social_accounts; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.social_accounts (
    id text NOT NULL,
    user_id text NOT NULL,
    provider character varying(50) NOT NULL,
    provider_id text NOT NULL,
    email text,
    display_name text,
    profile_data jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: users; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.users (
    id text NOT NULL,
    username character varying(50) NOT NULL,
    email text,
    password_hash text,
    display_name text,
    avatar_url text,
    bio text,
    website text,
    location text,
    is_active boolean DEFAULT true NOT NULL,
    is_verified boolean DEFAULT false NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    email_verification_token text,
    email_verification_expires_at timestamp with time zone,
    password_reset_token text,
    password_reset_expires_at timestamp with time zone,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    preferences jsonb DEFAULT '{}'::jsonb,
    privacy_settings jsonb DEFAULT '{}'::jsonb,
    notification_settings jsonb DEFAULT '{}'::jsonb
);

--
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.webauthn_credentials (
    id text NOT NULL,
    user_id text NOT NULL,
    credential_id text NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text NOT NULL,
    transport text[] NOT NULL,
    flags jsonb NOT NULL,
    authenticator jsonb NOT NULL,
    sign_count integer DEFAULT 0 NOT NULL,
    clone_warning boolean DEFAULT false NOT NULL,
    name text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

--
-- Name: webauthn_sessions; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.webauthn_sessions (
    id text NOT NULL,
    user_id text NOT NULL,
    challenge text NOT NULL,
    session_data jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

--
-- Name: cors_dynamic_origins; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.cors_dynamic_origins (
    id SERIAL PRIMARY KEY,
    origin text NOT NULL,
    oauth2_client_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (origin, oauth2_client_id)
);

--
-- Name: PRIMARY KEY constraints
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_pkey PRIMARY KEY (id);

-- ALTER TABLE ONLY public.schema_migrations
--     ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);

ALTER TABLE ONLY public.social_accounts
    ADD CONSTRAINT social_accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (id);

--
-- Name: UNIQUE constraints
--

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_code_hash_key UNIQUE (code_hash);

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_client_id_key UNIQUE (client_id);

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.social_accounts
    ADD CONSTRAINT social_accounts_provider_provider_id_key UNIQUE (provider, provider_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id);

--
-- Name: Indexes
--

CREATE INDEX idx_api_tokens_token_hash ON public.api_tokens USING btree (token_hash);
CREATE INDEX idx_api_tokens_type ON public.api_tokens USING btree (token_type);
CREATE INDEX idx_api_tokens_user_id ON public.api_tokens USING btree (user_id);
CREATE INDEX idx_oauth2_access_tokens_client_id ON public.oauth2_access_tokens USING btree (client_id);
CREATE INDEX idx_oauth2_access_tokens_expires_at ON public.oauth2_access_tokens USING btree (expires_at);
CREATE INDEX idx_oauth2_access_tokens_revoked_at ON public.oauth2_access_tokens USING btree (revoked_at);
CREATE INDEX idx_oauth2_access_tokens_token_hash ON public.oauth2_access_tokens USING btree (token_hash);
CREATE INDEX idx_oauth2_access_tokens_user_id ON public.oauth2_access_tokens USING btree (user_id);
CREATE INDEX idx_oauth2_auth_codes_client_id ON public.oauth2_authorization_codes USING btree (client_id);
CREATE INDEX idx_oauth2_auth_codes_code_hash ON public.oauth2_authorization_codes USING btree (code_hash);
CREATE INDEX idx_oauth2_auth_codes_expires_at ON public.oauth2_authorization_codes USING btree (expires_at);
CREATE INDEX idx_oauth2_auth_codes_used_at ON public.oauth2_authorization_codes USING btree (used_at);
CREATE INDEX idx_oauth2_auth_codes_user_id ON public.oauth2_authorization_codes USING btree (user_id);
CREATE INDEX idx_oauth2_clients_client_id ON public.oauth2_clients USING btree (client_id);
CREATE INDEX idx_oauth2_clients_created_at ON public.oauth2_clients USING btree (created_at);
CREATE INDEX idx_oauth2_clients_is_active ON public.oauth2_clients USING btree (is_active);
CREATE INDEX idx_oauth2_clients_user_id ON public.oauth2_clients USING btree (user_id);
CREATE INDEX idx_oauth2_refresh_tokens_access_token_id ON public.oauth2_refresh_tokens USING btree (access_token_id);
CREATE INDEX idx_oauth2_refresh_tokens_client_id ON public.oauth2_refresh_tokens USING btree (client_id);
CREATE INDEX idx_oauth2_refresh_tokens_expires_at ON public.oauth2_refresh_tokens USING btree (expires_at);
CREATE INDEX idx_oauth2_refresh_tokens_revoked_at ON public.oauth2_refresh_tokens USING btree (revoked_at);
CREATE INDEX idx_oauth2_refresh_tokens_token_hash ON public.oauth2_refresh_tokens USING btree (token_hash);
CREATE INDEX idx_oauth2_refresh_tokens_user_id ON public.oauth2_refresh_tokens USING btree (user_id);
CREATE INDEX idx_social_accounts_provider ON public.social_accounts USING btree (provider, provider_id);
CREATE INDEX idx_social_accounts_user_id ON public.social_accounts USING btree (user_id);
CREATE INDEX idx_users_email ON public.users USING btree (email) WHERE (email IS NOT NULL);
CREATE INDEX idx_users_username ON public.users USING btree (username);
CREATE INDEX idx_webauthn_credentials_credential_id ON public.webauthn_credentials USING btree (credential_id);
CREATE INDEX idx_webauthn_credentials_user_id ON public.webauthn_credentials USING btree (user_id);
CREATE INDEX idx_webauthn_sessions_challenge ON public.webauthn_sessions USING btree (challenge);
CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);
CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);
CREATE INDEX idx_cors_dynamic_origins_origin ON public.cors_dynamic_origins USING btree (origin);
CREATE INDEX idx_cors_dynamic_origins_client_id ON public.cors_dynamic_origins USING btree (oauth2_client_id);

--
-- Name: Triggers
--

CREATE TRIGGER update_oauth2_clients_updated_at BEFORE UPDATE ON public.oauth2_clients FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_social_accounts_updated_at BEFORE UPDATE ON public.social_accounts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_webauthn_credentials_updated_at BEFORE UPDATE ON public.webauthn_credentials FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

--
-- Name: Foreign Key constraints
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_access_token_id_fkey FOREIGN KEY (access_token_id) REFERENCES public.oauth2_access_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.social_accounts
    ADD CONSTRAINT social_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;