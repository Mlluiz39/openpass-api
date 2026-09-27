package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TB is the subset of *testing.T this package needs. Declaring it here keeps
// the production binary from importing the testing package.
type TB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

// TestDatabaseURL points the test suite at PostgreSQL. Tests do not need a
// dedicated server: every OpenTest call gets its own schema, so the dev
// database works fine as the default.
func TestDatabaseURL() string {
	if url := os.Getenv("OPENPASS_TEST_DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://openpass:openpass@localhost:5432/openpass?sslmode=disable"
}

// OpenTest returns a migrated database isolated in a fresh PostgreSQL schema.
// The schema is selected server-side through the standard libpq `options`
// startup parameter (`-c search_path=...`), so every connection the pool
// opens already points at the test schema — no client-side hook required and
// parallel tests never see each other's tables.
func OpenTest(tb TB) *sql.DB {
	tb.Helper()
	sourceURL := TestDatabaseURL()

	schema := "t_" + randomHex(8)
	if err := createSchema(sourceURL, schema); err != nil {
		tb.Fatalf("PostgreSQL unavailable for tests: %v\nRun `docker compose up -d db` or set OPENPASS_TEST_DATABASE_URL.", err)
	}

	cfg, err := pgx.ParseConfig(sourceURL)
	if err != nil {
		tb.Fatalf("parse test connection URL: %v", err)
	}
	applySearchPath(cfg, schema)

	database := stdlib.OpenDB(*cfg)
	if err := Migrate(database); err != nil {
		_ = database.Close()
		dropSchema(sourceURL, schema)
		tb.Fatalf("migrate test schema: %v", err)
	}

	tb.Cleanup(func() {
		_ = database.Close()
		dropSchema(sourceURL, schema)
	})
	return database
}

// applySearchPath sets the standard libpq `options` startup parameter so the
// server itself starts every connection of this pool in the test schema.
// Existing options in the connection string are preserved.
func applySearchPath(cfg *pgx.ConnConfig, schema string) {
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	option := "-c search_path=" + schema
	if existing := cfg.RuntimeParams["options"]; existing != "" {
		option = existing + " " + option
	}
	cfg.RuntimeParams["options"] = option
}

func createSchema(databaseURL, schema string) error {
	admin, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return err
	}
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	return err
}

func dropSchema(databaseURL, schema string) {
	admin, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return
	}
	defer admin.Close()
	_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
}

func randomHex(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
