-- Multi-user support.
--
-- The single shared admin (app_settings password + admin_sessions) is
-- replaced by per-user accounts. Existing ownerless rows cannot exist at
-- this point: fresh databases run every migration before any data is
-- inserted, and migrated databases are produced by cmd/migrate-sqlite,
-- which copies rows together with the owner they were assigned to.
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    recovery_key_enc TEXT,
    recovery_key_hash TEXT,
    invited_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

DROP TABLE IF EXISTS admin_sessions;

ALTER TABLE vaults ADD COLUMN owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE api_keys ADD COLUMN owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE backups ADD COLUMN owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE api_audit_logs ADD COLUMN owner_id TEXT REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_vaults_owner ON vaults(owner_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_backups_owner ON backups(owner_id);
CREATE INDEX IF NOT EXISTS idx_audit_owner ON api_audit_logs(owner_id);

-- The global password/recovery keys now live on the users table.
DELETE FROM app_settings
 WHERE key IN ('admin_password_salt', 'admin_password_hash', 'recovery_key_enc', 'recovery_key_hash');
