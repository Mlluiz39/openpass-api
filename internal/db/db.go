package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Open connects to PostgreSQL. databaseURL is a standard Postgres URL,
// e.g. postgres://user:pass@localhost:5432/openpass?sslmode=disable.
func Open(databaseURL string) (*sql.DB, error) {
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	// pgx connects lazily; ping so a bad URL fails at startup, not on the
	// first request.
	if err := database.Ping(); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	return database, nil
}

// Migrate applies every embedded migrations/*.sql file not yet recorded in
// schema_migrations, in filename order. Each file runs in its own transaction
// so a failure never leaves a half-applied migration behind.
func Migrate(database *sql.DB) error {
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	pending, err := pendingMigrations(database)
	if err != nil {
		return err
	}

	conn, err := database.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	for _, m := range pending {
		// Exec with no args goes through pgx's simple protocol, which is what
		// lets a whole SQL file (many statements) run as one unit.
		if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
			return fmt.Errorf("begin %s: %w", m.name, err)
		}
		if _, err := conn.ExecContext(ctx, m.sql); err != nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
			return fmt.Errorf("apply %s: %w", m.name, err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, applied_at) VALUES($1, $2)`,
			m.version, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
			return fmt.Errorf("record %s: %w", m.name, err)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return fmt.Errorf("commit %s: %w", m.name, err)
		}
	}
	return nil
}

type migration struct {
	version int
	name    string
	sql     string
}

var migrationFilename = regexp.MustCompile(`^(\d+)_.*\.sql$`)

func pendingMigrations(database *sql.DB) ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}

	applied := map[int]bool{}
	rows, err := database.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return nil, err
		}
		applied[version] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	var out []migration
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		match := migrationFilename.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		version, err := strconv.Atoi(match[1])
		if err != nil {
			return nil, err
		}
		if applied[version] {
			continue
		}
		raw, err := migrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: version, name: entry.Name(), sql: string(raw)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// IsUniqueViolation reports whether err is a PostgreSQL unique-constraint
// violation (SQLSTATE 23505). Handlers use it to turn the raw driver error
// into the user-facing "já existe um item com este nome" message.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var identifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// SanitizeIdentifier validates identifiers that must be interpolated into SQL
// (schema names, fixed allowlisted table names). Anything outside letters,
// digits and underscores is rejected, so no injection can sneak through.
func SanitizeIdentifier(value string) (string, error) {
	if !identifierPattern.MatchString(value) {
		return "", fmt.Errorf("invalid SQL identifier: %q", value)
	}
	return value, nil
}
