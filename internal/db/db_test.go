package db

import (
	"database/sql"
	"testing"
)

func TestOpenAndMigrateCreatesCoreTables(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := Migrate(database, CoreSchema); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	for _, table := range []string{
		"admin_sessions",
		"api_keys",
		"vaults",
		"entries",
		"backups",
		"api_audit_logs",
	} {
		assertTableExists(t, database, table)
	}
}

func TestOpenEnablesForeignKeys(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	var enabled int
	if err := database.QueryRow("PRAGMA foreign_keys").Scan(&enabled); err != nil {
		t.Fatalf("PRAGMA foreign_keys scan error = %v", err)
	}
	if enabled != 1 {
		t.Fatalf("foreign_keys = %d, want 1", enabled)
	}
}

func assertTableExists(t *testing.T, database *sql.DB, table string) {
	t.Helper()
	var name string
	err := database.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
		table,
	).Scan(&name)
	if err != nil {
		t.Fatalf("table %s missing: %v", table, err)
	}
}
