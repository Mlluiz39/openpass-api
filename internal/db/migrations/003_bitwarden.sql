-- Bitwarden API support for OpenPass.
--
-- Enables zero-knowledge encryption compatible with official Bitwarden clients
-- (browser extensions, mobile apps, desktop and CLI).

CREATE TABLE IF NOT EXISTS bitwarden_accounts (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    kdf_type INTEGER NOT NULL DEFAULT 0, -- 0 = PBKDF2_SHA256, 1 = Argon2id
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    kdf_memory INTEGER, -- in MB for Argon2id
    kdf_parallelism INTEGER, -- for Argon2id
    master_password_hint TEXT,
    user_key TEXT NOT NULL, -- Symmetric key encrypted with Master Key
    private_key TEXT, -- RSA Private key encrypted with user key
    public_key TEXT, -- RSA Public key
    security_stamp TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bitwarden_folders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL, -- Encrypted CipherString
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bitwarden_ciphers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id TEXT REFERENCES bitwarden_folders(id) ON DELETE SET NULL,
    organization_id TEXT,
    type INTEGER NOT NULL, -- 1=Login, 2=SecureNote, 3=Card, 4=Identity
    name TEXT NOT NULL, -- Encrypted CipherString
    notes TEXT, -- Encrypted CipherString
    data TEXT NOT NULL DEFAULT '{}', -- JSON with encrypted fields (login, card, identity, etc)
    favorite INTEGER NOT NULL DEFAULT 0,
    reprompt INTEGER NOT NULL DEFAULT 0,
    deleted_date TEXT, -- null if active, timestamp if in trash
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bitwarden_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_identifier TEXT,
    device_name TEXT,
    device_type INTEGER DEFAULT 0,
    refresh_token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bitwarden_sends (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    notes TEXT,
    text TEXT,
    type INTEGER NOT NULL DEFAULT 0, -- 0=Text, 1=File
    password_hash TEXT,
    max_access_count INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0,
    expiration_date TEXT,
    deletion_date TEXT,
    disabled INTEGER NOT NULL DEFAULT 0,
    hide_email INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bw_folders_user ON bitwarden_folders(user_id);
CREATE INDEX IF NOT EXISTS idx_bw_ciphers_user ON bitwarden_ciphers(user_id);
CREATE INDEX IF NOT EXISTS idx_bw_ciphers_folder ON bitwarden_ciphers(folder_id);
CREATE INDEX IF NOT EXISTS idx_bw_devices_user ON bitwarden_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_bw_devices_token ON bitwarden_devices(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_bw_sends_user ON bitwarden_sends(user_id);
