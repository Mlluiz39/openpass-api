// Command migrate-sqlite copies an existing OpenPass SQLite database into
// PostgreSQL, turning the old single-admin data into the first admin
// account's vault.
//
// The old panel password keeps working: its salt+hash are carried over in the
// legacy-sha256 format and transparently upgraded to argon2id on the first
// successful login. The recovery key is copied as-is (it is encrypted with
// the same app secret).
//
// Usage:
//
//	go run ./cmd/migrate-sqlite -admin-email voce@exemplo.com
//
// Flags:
//
//	-sqlite        path to the source SQLite file (default data/openpass.db)
//	-database-url  target PostgreSQL URL (default $DATABASE_URL)
//	-admin-email   e-mail for the first admin account (required)
//	-force         merge into a non-empty target, skipping rows by id
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
)

// copyTables are exported with their owner column; entries inherit ownership
// through vaults (which are copied with the same owner_id).
var copyTables = []string{
	"vaults",
	"entries",
	"api_keys",
	"backups",
	"api_audit_logs",
}

// timestampColumns are normalized from SQLite's "2006-01-02 15:04:05" format
// to RFC3339 UTC so ORDER BY created_at/updated_at stays consistent with rows
// the app writes after the migration.
var timestampColumns = map[string]bool{
	"created_at":   true,
	"updated_at":   true,
	"last_used_at": true,
	"expires_at":   true,
}

func main() {
	sqlitePath := flag.String("sqlite", "data/openpass.db", "path to the source SQLite database")
	databaseURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "target PostgreSQL URL (defaults to $DATABASE_URL)")
	adminEmail := flag.String("admin-email", "", "e-mail for the first admin account that will own the migrated data")
	force := flag.Bool("force", false, "merge into a non-empty target, skipping rows that already exist")
	flag.Parse()

	if *adminEmail == "" {
		fatal("-admin-email is required (the e-mail you will use to log in after the migration)")
	}
	if *databaseURL == "" {
		*databaseURL = "postgres://openpass:openpass@localhost:5432/openpass?sslmode=disable"
	}

	source, err := sql.Open("sqlite", "file:"+*sqlitePath+"?mode=ro")
	if err != nil {
		fatal("open sqlite: %v", err)
	}
	defer source.Close()
	if err := source.Ping(); err != nil {
		fatal("read sqlite %s: %v (run this from the directory that holds your old database)", *sqlitePath, err)
	}

	target, err := opdb.Open(*databaseURL)
	if err != nil {
		fatal("open postgres: %v", err)
	}
	defer target.Close()
	if err := opdb.Migrate(target); err != nil {
		fatal("migrate postgres schema: %v", err)
	}

	settings, err := readSettings(source)
	if err != nil {
		fatal("read app_settings: %v", err)
	}

	ownerID, created, err := ensureAdmin(target, *adminEmail, settings, *force)
	if err != nil {
		fatal("%v", err)
	}
	if created {
		fmt.Printf("→ admin account created: %s (id %s)\n", *adminEmail, ownerID)
	} else {
		fmt.Printf("→ reusing existing account %s (id %s)\n", *adminEmail, ownerID)
	}

	total := 0
	for _, table := range copyTables {
		count, err := copyTable(source, target, table, ownerID, *force)
		if err != nil {
			fatal("copy %s: %v", table, err)
		}
		fmt.Printf("→ %-16s %d rows\n", table, count)
		total += count
	}

	fmt.Printf("\nMigration complete: %d rows copied into the account %s.\n", total, *adminEmail)
	fmt.Println("Start the app against PostgreSQL and log in with the OLD panel password;")
	fmt.Println("the first successful login upgrades the stored hash to argon2id.")
}

// ensureAdmin finds or creates the owning admin account. The password comes
// from the legacy app_settings hash when available (so the old panel password
// still works), otherwise from OPENPASS_ADMIN_PASSWORD.
func ensureAdmin(db *sql.DB, email string, settings map[string]string, force bool) (string, bool, error) {
	// Already-migrated target: reuse the account with this e-mail.
	var existingID string
	err := db.QueryRow(`SELECT id FROM users WHERE email = $1`, normalizeEmail(email)).Scan(&existingID)
	if err == nil {
		return existingID, false, nil
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}

	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount); err != nil {
		return "", false, err
	}
	if userCount > 0 {
		if !force {
			return "", false, fmt.Errorf("target database already has %d user(s); use -force to merge into an existing account with the same e-mail, or migrate into an empty database", userCount)
		}
		return "", false, fmt.Errorf("target database has users but none with e-mail %s; refusing to guess the owner", normalizeEmail(email))
	}

	passwordHash := secure.BuildLegacyHash(settings["admin_password_salt"], settings["admin_password_hash"])
	if passwordHash == "" {
		// Fresh export without a stored password: fall back to the env var.
		password := os.Getenv("OPENPASS_ADMIN_PASSWORD")
		if password == "" {
			return "", false, fmt.Errorf("no legacy password hash found in SQLite and OPENPASS_ADMIN_PASSWORD is not set")
		}
		var err error
		passwordHash, err = secure.HashPassword(password)
		if err != nil {
			return "", false, err
		}
		fmt.Println("→ no legacy password in source; using OPENPASS_ADMIN_PASSWORD (argon2id)")
	}

	id, err := randomID()
	if err != nil {
		return "", false, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var recoveryEnc, recoveryHash any
	if settings["recovery_key_enc"] != "" {
		recoveryEnc = settings["recovery_key_enc"]
	}
	if settings["recovery_key_hash"] != "" {
		recoveryHash = settings["recovery_key_hash"]
	}
	_, err = db.Exec(`INSERT INTO users(
		id, email, display_name, password_hash, role, status, must_change_password,
		recovery_key_enc, recovery_key_hash, created_at, updated_at
	) VALUES($1,$2,'Administrador',$3,'admin','active',0,$4,$5,$6,$7)`,
		id, normalizeEmail(email), passwordHash, recoveryEnc, recoveryHash, now, now,
	)
	if err != nil {
		return "", false, fmt.Errorf("create admin: %w", err)
	}
	return id, true, nil
}

func copyTable(source, target *sql.DB, table, ownerID string, force bool) (int, error) {
	rows, err := source.Query("SELECT * FROM " + table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	// entries has no owner_id of its own: ownership comes from vaults, which
	// are copied with this same owner.
	sourceCount := len(columns)
	if table != "entries" && !slices.Contains(columns, "owner_id") {
		columns = append(columns, "owner_id")
	}

	placeholders := make([]string, len(columns))
	for i := range columns {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	conflict := ""
	if force {
		// Idempotent merge: a retried migration must not fail on primary keys.
		conflict = " ON CONFLICT (id) DO NOTHING"
	}
	query := fmt.Sprintf("INSERT INTO %s(%s) VALUES(%s)%s",
		table, strings.Join(columns, ","), strings.Join(placeholders, ","), conflict)

	count := 0
	for rows.Next() {
		values := make([]any, len(columns))
		scanTargets := make([]any, sourceCount)
		for i := range scanTargets {
			scanTargets[i] = &values[i]
		}
		if err := rows.Scan(scanTargets...); err != nil {
			return count, err
		}
		for i, column := range columns[:sourceCount] {
			values[i] = normalizeValue(values[i])
			if timestampColumns[column] {
				values[i] = convertTimestamp(values[i])
			}
		}
		if len(columns) > sourceCount {
			values[sourceCount] = ownerID
		}

		if _, err := target.Exec(query, values...); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

func readSettings(source *sql.DB) (map[string]string, error) {
	rows, err := source.Query(`SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, rows.Err()
}

// normalizeValue turns driver values into what PostgreSQL expects: SQLite
// hands TEXT columns over as []byte sometimes.
func normalizeValue(value any) any {
	switch v := value.(type) {
	case []byte:
		return string(v)
	case nil:
		return nil
	default:
		return v
	}
}

// convertTimestamp maps SQLite's CURRENT_TIMESTAMP format to RFC3339 UTC.
// Values already in RFC3339 (or anything unparseable) pass through unchanged.
func convertTimestamp(value any) any {
	str, ok := value.(string)
	if !ok || str == "" {
		return value
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.000",
		time.RFC3339,
	} {
		if parsed, err := time.Parse(layout, str); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return value
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
