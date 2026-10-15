CREATE TABLE IF NOT EXISTS configuration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 protocol text NOT NULL,
 server_key_material bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
 id text PRIMARY KEY,
 username text NOT NULL UNIQUE,
 credential_id bytea NOT NULL UNIQUE,
 record bytea NOT NULL,
 wrapped_key jsonb NOT NULL,
 recovery_public_key jsonb NOT NULL,
 recovery_wrapped_key jsonb,
 email text UNIQUE,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS challenges (
 id text PRIMARY KEY,
 kind text NOT NULL CHECK(kind IN ('registration','login','recovery')),
 username text NOT NULL,
 account_id text,
 credential_id bytea,
 expected_mac bytea,
 session_secret bytea,
 proof_key jsonb,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires_at);
CREATE TABLE IF NOT EXISTS devices (
 id text PRIMARY KEY,
 account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 token_hash bytea NOT NULL UNIQUE,
 proof_key jsonb NOT NULL,
 thumbprint text NOT NULL,
 name text NOT NULL,
 scope text NOT NULL,
 origin text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
CREATE TABLE IF NOT EXISTS vaults (
 account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 scope text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 ciphertext jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(account_id,scope)
);
CREATE TABLE IF NOT EXISTS authorizations (
 id text PRIMARY KEY,
 client_id text NOT NULL,
 redirect_uri text NOT NULL,
 code_challenge text NOT NULL,
 request_hash text NOT NULL,
 state text NOT NULL,
 proof_key jsonb NOT NULL,
 name text NOT NULL,
 account_id text REFERENCES accounts(id) ON DELETE CASCADE,
 approved_by text REFERENCES devices(id),
 code_hash bytea UNIQUE,
 wrapped_scope_key jsonb,
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS authorizations_expiry ON authorizations(expires_at);
CREATE TABLE IF NOT EXISTS proof_replays (
 thumbprint text NOT NULL,
 jti text NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(thumbprint,jti)
);
CREATE INDEX IF NOT EXISTS proof_replays_expiry ON proof_replays(expires_at);
CREATE TABLE IF NOT EXISTS rate_limits (
 bucket text PRIMARY KEY,
 started_at timestamptz NOT NULL,
 count integer NOT NULL
);
CREATE TABLE IF NOT EXISTS email_challenges (
 id text PRIMARY KEY,
 token_hash bytea NOT NULL UNIQUE,
 account_id text REFERENCES accounts(id) ON DELETE CASCADE,
 email text NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('registration','authentication','recovery','link')),
 proof_key jsonb NOT NULL,
 thumbprint text NOT NULL,
 expires_at timestamptz NOT NULL,
 verified_at timestamptz,
 consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS email_challenges_expiry ON email_challenges(expires_at);
