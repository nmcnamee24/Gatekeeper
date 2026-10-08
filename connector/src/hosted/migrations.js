// Serialized by a transaction-scoped advisory lock; never run destructive upgrades.
export const HOSTED_SCHEMA = `
CREATE TABLE IF NOT EXISTS gk_users (
 id uuid PRIMARY KEY, apple_sub text UNIQUE NOT NULL, display_name text,
 consent_version text, cooldown_until timestamptz, apple_refresh_ciphertext text,
 apple_refresh_client_id text, apple_verified_at timestamptz,
 apple_next_check_at timestamptz, apple_check_lease_token uuid,
 apple_check_lease_until timestamptz, apple_check_attempts integer NOT NULL DEFAULT 0,
 apple_authorization_revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_refresh_client_id text;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_verified_at timestamptz;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_next_check_at timestamptz;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_check_lease_token uuid;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_check_lease_until timestamptz;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_check_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS apple_authorization_revoked_at timestamptz;
ALTER TABLE gk_users ADD COLUMN IF NOT EXISTS purchase_account_token uuid;
CREATE UNIQUE INDEX IF NOT EXISTS gk_users_purchase_account_token ON gk_users(purchase_account_token);
UPDATE gk_users SET apple_next_check_at=COALESCE(apple_verified_at + INTERVAL '1 day',now())
 WHERE apple_refresh_ciphertext IS NOT NULL AND apple_next_check_at IS NULL AND apple_authorization_revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS gk_users_apple_check_due ON gk_users(apple_next_check_at,id)
 WHERE apple_refresh_ciphertext IS NOT NULL AND apple_authorization_revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS gk_devices (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
 name text NOT NULL, installation_id text NOT NULL, token_hash text UNIQUE NOT NULL,
 revoked_at timestamptz, apns_token text, apns_environment text,
 last_seen_at timestamptz, UNIQUE(user_id,installation_id), UNIQUE(id,user_id)
);
CREATE TABLE IF NOT EXISTS gk_sessions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
 device_id uuid, token_hash text UNIQUE NOT NULL, refresh_hash text UNIQUE NOT NULL,
 kind text NOT NULL CHECK(kind IN ('account','agent')), scopes text[] NOT NULL DEFAULT '{}',
 expires_at timestamptz NOT NULL, refresh_expires_at timestamptz NOT NULL,
 revoked_at timestamptz, refresh_used_at timestamptz, family_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE
);
ALTER TABLE gk_sessions ADD COLUMN IF NOT EXISTS family_id uuid;
ALTER TABLE gk_sessions ADD COLUMN IF NOT EXISTS refresh_used_at timestamptz;
UPDATE gk_sessions SET family_id=id WHERE family_id IS NULL;
ALTER TABLE gk_sessions ALTER COLUMN family_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS gk_sessions_family ON gk_sessions(user_id,family_id);
CREATE INDEX IF NOT EXISTS gk_sessions_user_device ON gk_sessions(user_id,device_id);
CREATE INDEX IF NOT EXISTS gk_sessions_retention ON gk_sessions(refresh_expires_at);
CREATE TABLE IF NOT EXISTS gk_grants (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
 device_id uuid NOT NULL, request_id text NOT NULL, request_fingerprint text NOT NULL,
 purpose text, exit_plan text, window_seconds integer NOT NULL CHECK(window_seconds BETWEEN 60 AND 900),
 created_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 redeemed_at timestamptz, ends_at timestamptz, revoked_at timestamptz,
 FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE,
 UNIQUE(user_id,request_id), UNIQUE(id,user_id,device_id)
);
ALTER TABLE gk_grants ADD COLUMN IF NOT EXISTS ordinal bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE gk_grants ADD COLUMN IF NOT EXISTS access_source text NOT NULL DEFAULT 'legacy_beta'
 CHECK(access_source IN ('legacy_beta','beta','production_paid','sandbox_test'));
CREATE INDEX IF NOT EXISTS gk_grants_user_created ON gk_grants(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS gk_grants_retention ON gk_grants(created_at) WHERE purpose IS NOT NULL OR exit_plan IS NOT NULL;
CREATE TABLE IF NOT EXISTS gk_device_reports (
 device_id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
 received_at timestamptz NOT NULL, state text NOT NULL, grant_id uuid, local_expiry timestamptz,
 FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS gk_device_reports_user ON gk_device_reports(user_id);
CREATE TABLE IF NOT EXISTS gk_auth_challenges (
 id uuid PRIMARY KEY, nonce_hash text NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS gk_auth_challenges_retention ON gk_auth_challenges(expires_at);
CREATE TABLE IF NOT EXISTS gk_push_jobs (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES gk_users(id) ON DELETE CASCADE,
 device_id uuid NOT NULL, grant_id uuid, event text NOT NULL,
 created_at timestamptz NOT NULL, available_at timestamptz NOT NULL,
 lease_until timestamptz, lease_token uuid, attempts integer NOT NULL DEFAULT 0,
 completed_at timestamptz, FOREIGN KEY(device_id,user_id) REFERENCES gk_devices(id,user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS gk_push_jobs_user_device ON gk_push_jobs(user_id,device_id);
CREATE INDEX IF NOT EXISTS gk_push_jobs_retention ON gk_push_jobs(created_at);
CREATE INDEX IF NOT EXISTS gk_push_jobs_due ON gk_push_jobs(available_at) WHERE completed_at IS NULL;
`;
export async function migrateHosted(pool) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('gatekeeper-hosted-migration'))",
    );
    await client.query(HOSTED_SCHEMA);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
