--
-- PostgreSQL database dump
--

-- Dumped from database version 15.13
-- Dumped by pg_dump version 16.2

-- Started on 2025-07-15 20:21:13

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
-- TOC entry 2 (class 3079 OID 16392)
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- TOC entry 3570 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- TOC entry 235 (class 1255 OID 16461)
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


ALTER FUNCTION public.update_updated_at_column() OWNER TO glen_dev;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 219 (class 1259 OID 16442)
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


ALTER TABLE public.api_tokens OWNER TO glen_dev;

--
-- TOC entry 223 (class 1259 OID 32872)
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


ALTER TABLE public.oauth2_access_tokens OWNER TO glen_dev;

--
-- TOC entry 222 (class 1259 OID 32849)
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


ALTER TABLE public.oauth2_authorization_codes OWNER TO glen_dev;

--
-- TOC entry 221 (class 1259 OID 32829)
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


ALTER TABLE public.oauth2_clients OWNER TO glen_dev;

--
-- TOC entry 224 (class 1259 OID 32894)
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


ALTER TABLE public.oauth2_refresh_tokens OWNER TO glen_dev;

--
-- TOC entry 215 (class 1259 OID 16385)
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.schema_migrations (
    version character varying(255) NOT NULL,
    dirty boolean DEFAULT false NOT NULL,
    applied_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.schema_migrations OWNER TO glen_dev;

--
-- TOC entry 218 (class 1259 OID 16431)
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


ALTER TABLE public.social_accounts OWNER TO glen_dev;

--
-- TOC entry 216 (class 1259 OID 16403)
-- Name: users; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.users (
    id text NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(255),
    password_hash text,
    email_verified boolean DEFAULT false,
    status character varying(20) DEFAULT 'active'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.users OWNER TO glen_dev;

--
-- TOC entry 217 (class 1259 OID 16418)
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.webauthn_credentials (
    id text NOT NULL,
    user_id text NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint DEFAULT 0,
    name text DEFAULT 'Security Key'::text NOT NULL,
    transport text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone,
    attestation_type character varying(50) DEFAULT 'none'::character varying,
    flags jsonb DEFAULT '{}'::jsonb,
    clone_warning boolean DEFAULT false,
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.webauthn_credentials OWNER TO glen_dev;

--
-- TOC entry 220 (class 1259 OID 24579)
-- Name: webauthn_sessions; Type: TABLE; Schema: public; Owner: glen_dev
--

CREATE TABLE public.webauthn_sessions (
    id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
    challenge bytea NOT NULL,
    allowed_credential_ids jsonb,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    user_verification character varying(20) DEFAULT 'preferred'::character varying
);


ALTER TABLE public.webauthn_sessions OWNER TO glen_dev;

--
-- TOC entry 3366 (class 2606 OID 16449)
-- Name: api_tokens api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);


--
-- TOC entry 3368 (class 2606 OID 16451)
-- Name: api_tokens api_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash);


--
-- TOC entry 3400 (class 2606 OID 32881)
-- Name: oauth2_access_tokens oauth2_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_pkey PRIMARY KEY (id);


--
-- TOC entry 3402 (class 2606 OID 32883)
-- Name: oauth2_access_tokens oauth2_access_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_token_hash_key UNIQUE (token_hash);


--
-- TOC entry 3391 (class 2606 OID 32861)
-- Name: oauth2_authorization_codes oauth2_authorization_codes_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_code_hash_key UNIQUE (code_hash);


--
-- TOC entry 3393 (class 2606 OID 32859)
-- Name: oauth2_authorization_codes oauth2_authorization_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_pkey PRIMARY KEY (id);


--
-- TOC entry 3382 (class 2606 OID 32843)
-- Name: oauth2_clients oauth2_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_client_id_key UNIQUE (client_id);


--
-- TOC entry 3384 (class 2606 OID 32841)
-- Name: oauth2_clients oauth2_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_pkey PRIMARY KEY (id);


--
-- TOC entry 3410 (class 2606 OID 32902)
-- Name: oauth2_refresh_tokens oauth2_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_pkey PRIMARY KEY (id);


--
-- TOC entry 3412 (class 2606 OID 32904)
-- Name: oauth2_refresh_tokens oauth2_refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- TOC entry 3342 (class 2606 OID 16391)
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- TOC entry 3362 (class 2606 OID 16439)
-- Name: social_accounts social_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.social_accounts
    ADD CONSTRAINT social_accounts_pkey PRIMARY KEY (id);


--
-- TOC entry 3364 (class 2606 OID 16441)
-- Name: social_accounts social_accounts_provider_provider_id_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.social_accounts
    ADD CONSTRAINT social_accounts_provider_provider_id_key UNIQUE (provider, provider_id);


--
-- TOC entry 3346 (class 2606 OID 16417)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 3348 (class 2606 OID 16413)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- TOC entry 3350 (class 2606 OID 16415)
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- TOC entry 3356 (class 2606 OID 24596)
-- Name: webauthn_credentials webauthn_credentials_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id);


--
-- TOC entry 3358 (class 2606 OID 16428)
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- TOC entry 3376 (class 2606 OID 24587)
-- Name: webauthn_sessions webauthn_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (id);


--
-- TOC entry 3369 (class 1259 OID 16459)
-- Name: idx_api_tokens_token_hash; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_api_tokens_token_hash ON public.api_tokens USING btree (token_hash);


--
-- TOC entry 3370 (class 1259 OID 16460)
-- Name: idx_api_tokens_type; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_api_tokens_type ON public.api_tokens USING btree (token_type);


--
-- TOC entry 3371 (class 1259 OID 16458)
-- Name: idx_api_tokens_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_api_tokens_user_id ON public.api_tokens USING btree (user_id);


--
-- TOC entry 3394 (class 1259 OID 32930)
-- Name: idx_oauth2_access_tokens_client_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_access_tokens_client_id ON public.oauth2_access_tokens USING btree (client_id);


--
-- TOC entry 3395 (class 1259 OID 32932)
-- Name: idx_oauth2_access_tokens_expires_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_access_tokens_expires_at ON public.oauth2_access_tokens USING btree (expires_at);


--
-- TOC entry 3396 (class 1259 OID 32933)
-- Name: idx_oauth2_access_tokens_revoked_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_access_tokens_revoked_at ON public.oauth2_access_tokens USING btree (revoked_at);


--
-- TOC entry 3397 (class 1259 OID 32929)
-- Name: idx_oauth2_access_tokens_token_hash; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE UNIQUE INDEX idx_oauth2_access_tokens_token_hash ON public.oauth2_access_tokens USING btree (token_hash);


--
-- TOC entry 3398 (class 1259 OID 32931)
-- Name: idx_oauth2_access_tokens_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_access_tokens_user_id ON public.oauth2_access_tokens USING btree (user_id);


--
-- TOC entry 3385 (class 1259 OID 32925)
-- Name: idx_oauth2_auth_codes_client_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_auth_codes_client_id ON public.oauth2_authorization_codes USING btree (client_id);


--
-- TOC entry 3386 (class 1259 OID 32924)
-- Name: idx_oauth2_auth_codes_code_hash; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE UNIQUE INDEX idx_oauth2_auth_codes_code_hash ON public.oauth2_authorization_codes USING btree (code_hash);


--
-- TOC entry 3387 (class 1259 OID 32927)
-- Name: idx_oauth2_auth_codes_expires_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_auth_codes_expires_at ON public.oauth2_authorization_codes USING btree (expires_at);


--
-- TOC entry 3388 (class 1259 OID 32928)
-- Name: idx_oauth2_auth_codes_used_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_auth_codes_used_at ON public.oauth2_authorization_codes USING btree (used_at);


--
-- TOC entry 3389 (class 1259 OID 32926)
-- Name: idx_oauth2_auth_codes_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_auth_codes_user_id ON public.oauth2_authorization_codes USING btree (user_id);


--
-- TOC entry 3377 (class 1259 OID 32921)
-- Name: idx_oauth2_clients_client_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE UNIQUE INDEX idx_oauth2_clients_client_id ON public.oauth2_clients USING btree (client_id);


--
-- TOC entry 3378 (class 1259 OID 32923)
-- Name: idx_oauth2_clients_created_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_clients_created_at ON public.oauth2_clients USING btree (created_at);


--
-- TOC entry 3379 (class 1259 OID 32922)
-- Name: idx_oauth2_clients_is_active; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_clients_is_active ON public.oauth2_clients USING btree (is_active);


--
-- TOC entry 3380 (class 1259 OID 32920)
-- Name: idx_oauth2_clients_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_clients_user_id ON public.oauth2_clients USING btree (user_id);


--
-- TOC entry 3403 (class 1259 OID 32935)
-- Name: idx_oauth2_refresh_tokens_access_token_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_refresh_tokens_access_token_id ON public.oauth2_refresh_tokens USING btree (access_token_id);


--
-- TOC entry 3404 (class 1259 OID 32936)
-- Name: idx_oauth2_refresh_tokens_client_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_refresh_tokens_client_id ON public.oauth2_refresh_tokens USING btree (client_id);


--
-- TOC entry 3405 (class 1259 OID 32938)
-- Name: idx_oauth2_refresh_tokens_expires_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_refresh_tokens_expires_at ON public.oauth2_refresh_tokens USING btree (expires_at);


--
-- TOC entry 3406 (class 1259 OID 32939)
-- Name: idx_oauth2_refresh_tokens_revoked_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_refresh_tokens_revoked_at ON public.oauth2_refresh_tokens USING btree (revoked_at);


--
-- TOC entry 3407 (class 1259 OID 32934)
-- Name: idx_oauth2_refresh_tokens_token_hash; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE UNIQUE INDEX idx_oauth2_refresh_tokens_token_hash ON public.oauth2_refresh_tokens USING btree (token_hash);


--
-- TOC entry 3408 (class 1259 OID 32937)
-- Name: idx_oauth2_refresh_tokens_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_oauth2_refresh_tokens_user_id ON public.oauth2_refresh_tokens USING btree (user_id);


--
-- TOC entry 3359 (class 1259 OID 16457)
-- Name: idx_social_accounts_provider; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_social_accounts_provider ON public.social_accounts USING btree (provider, provider_id);


--
-- TOC entry 3360 (class 1259 OID 16456)
-- Name: idx_social_accounts_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_social_accounts_user_id ON public.social_accounts USING btree (user_id);


--
-- TOC entry 3343 (class 1259 OID 16453)
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_users_email ON public.users USING btree (email) WHERE (email IS NOT NULL);


--
-- TOC entry 3344 (class 1259 OID 16452)
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_users_username ON public.users USING btree (username);


--
-- TOC entry 3351 (class 1259 OID 24577)
-- Name: idx_webauthn_credentials_created_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_credentials_created_at ON public.webauthn_credentials USING btree (created_at);


--
-- TOC entry 3352 (class 1259 OID 24597)
-- Name: idx_webauthn_credentials_credential_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_credentials_credential_id ON public.webauthn_credentials USING btree (credential_id);


--
-- TOC entry 3353 (class 1259 OID 24578)
-- Name: idx_webauthn_credentials_last_used_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_credentials_last_used_at ON public.webauthn_credentials USING btree (last_used_at);


--
-- TOC entry 3354 (class 1259 OID 16454)
-- Name: idx_webauthn_credentials_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_credentials_user_id ON public.webauthn_credentials USING btree (user_id);


--
-- TOC entry 3372 (class 1259 OID 24590)
-- Name: idx_webauthn_sessions_created_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_sessions_created_at ON public.webauthn_sessions USING btree (created_at);


--
-- TOC entry 3373 (class 1259 OID 24589)
-- Name: idx_webauthn_sessions_expires_at; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_sessions_expires_at ON public.webauthn_sessions USING btree (expires_at);


--
-- TOC entry 3374 (class 1259 OID 24588)
-- Name: idx_webauthn_sessions_user_id; Type: INDEX; Schema: public; Owner: glen_dev
--

CREATE INDEX idx_webauthn_sessions_user_id ON public.webauthn_sessions USING btree (user_id);


--
-- TOC entry 3422 (class 2620 OID 16463)
-- Name: social_accounts update_social_accounts_updated_at; Type: TRIGGER; Schema: public; Owner: glen_dev
--

CREATE TRIGGER update_social_accounts_updated_at BEFORE UPDATE ON public.social_accounts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- TOC entry 3421 (class 2620 OID 16462)
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: glen_dev
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- TOC entry 3416 (class 2606 OID 32884)
-- Name: oauth2_access_tokens oauth2_access_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;


--
-- TOC entry 3417 (class 2606 OID 32889)
-- Name: oauth2_access_tokens oauth2_access_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_access_tokens
    ADD CONSTRAINT oauth2_access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 3414 (class 2606 OID 32862)
-- Name: oauth2_authorization_codes oauth2_authorization_codes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;


--
-- TOC entry 3415 (class 2606 OID 32867)
-- Name: oauth2_authorization_codes oauth2_authorization_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_authorization_codes
    ADD CONSTRAINT oauth2_authorization_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 3413 (class 2606 OID 32844)
-- Name: oauth2_clients oauth2_clients_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- TOC entry 3418 (class 2606 OID 32905)
-- Name: oauth2_refresh_tokens oauth2_refresh_tokens_access_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_access_token_id_fkey FOREIGN KEY (access_token_id) REFERENCES public.oauth2_access_tokens(id) ON DELETE CASCADE;


--
-- TOC entry 3419 (class 2606 OID 32910)
-- Name: oauth2_refresh_tokens oauth2_refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(client_id) ON DELETE CASCADE;


--
-- TOC entry 3420 (class 2606 OID 32915)
-- Name: oauth2_refresh_tokens oauth2_refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: glen_dev
--

ALTER TABLE ONLY public.oauth2_refresh_tokens
    ADD CONSTRAINT oauth2_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


-- Completed on 2025-07-15 20:21:13

--
-- PostgreSQL database dump complete
--

