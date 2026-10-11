-- Bitwarden core support (companion to 003_bitwarden.sql).
--
-- Adds the pieces the identity/API layer needs on top of the base tables:
-- the master-password hash (zero-knowledge: the server only ever sees the
-- client-derived key hash), authenticator 2FA, per-cipher keys and the RSA
-- signing key used for JWT access tokens.

-- Master password hash (PBKDF2 of the client-derived master key) plus 2FA
-- and equivalent-domain settings, mirroring the upstream users table.
ALTER TABLE bitwarden_accounts ADD COLUMN password_hash TEXT;
ALTER TABLE bitwarden_accounts ADD COLUMN two_factor_secret TEXT;
ALTER TABLE bitwarden_accounts ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bitwarden_accounts ADD COLUMN equivalent_domains TEXT NOT NULL DEFAULT '[]';
ALTER TABLE bitwarden_accounts ADD COLUMN excluded_globals TEXT NOT NULL DEFAULT '[]';
ALTER TABLE bitwarden_accounts ADD COLUMN avatar_color TEXT;

-- Optional per-cipher encryption key and the extra encrypted sub-objects.
ALTER TABLE bitwarden_ciphers ADD COLUMN key TEXT;
ALTER TABLE bitwarden_ciphers ADD COLUMN fields TEXT;
ALTER TABLE bitwarden_ciphers ADD COLUMN password_history TEXT;

-- 2FA "remember this device" token and push registration.
ALTER TABLE bitwarden_devices ADD COLUMN twofactor_remember TEXT;
ALTER TABLE bitwarden_devices ADD COLUMN push_token TEXT;
-- A device registers on its first login, before any refresh token exists.
ALTER TABLE bitwarden_devices ALTER COLUMN refresh_token_hash DROP NOT NULL;

-- RSA key pair used to sign identity JWTs (served as JWKS).
CREATE TABLE IF NOT EXISTS bitwarden_service_keys (
    kid TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bw_accounts_hash ON bitwarden_accounts(password_hash);
