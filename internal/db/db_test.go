package db

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMigrateCreatesCoreTablesAndRecordsVersions(t *testing.T) {
	database := OpenTest(t)

	for _, table := range []string{
		"users",
		"sessions",
		"api_keys",
		"vaults",
		"entries",
		"backups",
		"api_audit_logs",
		"app_settings",
	} {
		assertTableExists(t, database, table)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("schema_migrations query: %v", err)
	}
	if count == 0 {
		t.Fatalf("schema_migrations is empty, want recorded migrations")
	}

	// Running Migrate again must be a no-op, not an error.
	if err := Migrate(database); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	database := OpenTest(t)

	_, err := database.Exec(
		`INSERT INTO entries(id, vault_id, path, type, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6)`,
		"e1", "does-not-exist", "path", "login", now(), now(),
	)
	if err == nil {
		t.Fatalf("insert with unknown vault_id succeeded, want foreign key error")
	}
}

func TestIsUniqueViolationDetectsSQLState23505(t *testing.T) {
	database := OpenTest(t)
	owner := insertTestUser(t, database, "uniq-owner")
	stmt := `INSERT INTO vaults(id, name, description, owner_id, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6)`
	args := []any{"v1", "dup", "", owner, now(), now()}

	if _, err := database.Exec(stmt, args...); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, err := database.Exec(stmt, args...)
	if err == nil {
		t.Fatalf("duplicate insert succeeded, want unique violation")
	}
	if !IsUniqueViolation(err) {
		t.Fatalf("IsUniqueViolation() = false for %v", err)
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || !strings.HasPrefix(pgErr.Code, "23") {
		t.Fatalf("unexpected error type: %v", err)
	}
}

func assertTableExists(t *testing.T, database *sql.DB, table string) {
	t.Helper()
	var name string
	err := database.QueryRow(
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_name = $1`,
		table,
	).Scan(&name)
	if err != nil {
		t.Fatalf("table %s missing: %v", table, err)
	}
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// insertTestUser creates the owner row a vault has to point at.
func insertTestUser(t *testing.T, database *sql.DB, id string) string {
	t.Helper()
	_, err := database.Exec(`INSERT INTO users(id, email, password_hash, role, status, must_change_password, created_at, updated_at)
		VALUES($1, $2, 'argon2id$test', 'user', 'active', 0, $3, $3)`,
		id, id+"@test.local", now(),
	)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	return id
}
