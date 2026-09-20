package db

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const CoreSchema = `
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
`

func Open(path string) (*sql.DB, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := applyPragmas(database); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func Migrate(database *sql.DB, schema string) error {
	if err := resetEmptyLegacySchema(database); err != nil {
		return err
	}
	_, err := database.Exec(schema)
	return err
}

func applyPragmas(database *sql.DB) error {
	for _, stmt := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := database.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func resetEmptyLegacySchema(database *sql.DB) error {
	legacy, err := hasTableWithoutColumn(database, "api_keys", "encrypted_token")
	if err != nil || !legacy {
		return err
	}

	for _, table := range []string{"api_keys", "vaults", "entries", "backups", "api_audit_logs"} {
		count, err := tableCount(database, table)
		if err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
	}

	for _, table := range []string{"api_audit_logs", "backups", "entries", "vaults", "api_keys", "users", "admin_sessions"} {
		if _, err := database.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			return err
		}
	}
	return nil
}

func hasTableWithoutColumn(database *sql.DB, table, column string) (bool, error) {
	rows, err := database.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	foundTable := false
	foundColumn := false
	for rows.Next() {
		foundTable = true
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			foundColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return foundTable && !foundColumn, nil
}

func tableCount(database *sql.DB, table string) (int, error) {
	var exists string
	err := database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&exists)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
