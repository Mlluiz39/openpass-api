CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_suffix TEXT NOT NULL,
    encrypted_token TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '{}',
    allowed_ips TEXT,
    vault_scope TEXT,
    rate_limit_rpm INTEGER DEFAULT 60,
    is_active INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    path TEXT NOT NULL,
    type TEXT NOT NULL,
    encrypted_value TEXT,
    metadata TEXT,
    tags TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    UNIQUE(vault_id, path)
);

CREATE TABLE IF NOT EXISTS backups (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    size_bytes INTEGER,
    format TEXT DEFAULT 'zip',
    status TEXT DEFAULT 'completed',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_audit_logs (
    id TEXT PRIMARY KEY,
    api_key_id TEXT,
    key_prefix TEXT,
    ip_address TEXT,
    user_agent TEXT,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms INTEGER,
    result TEXT NOT NULL CHECK (result IN ('success', 'denied', 'error')),
    error_msg TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix, is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_entries_vault ON entries(vault_id);
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON api_audit_logs(api_key_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON api_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ip ON api_audit_logs(ip_address);
