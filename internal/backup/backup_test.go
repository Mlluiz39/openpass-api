package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
)

const testOwnerID = "owner-1"

func TestExportIsEncryptedAndRestoreRecoversData(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), testOwnerID, "backup-pass")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if file.Filename == "" || !strings.HasSuffix(file.Filename, ".opbackup") {
		t.Fatalf("Filename = %q, want .opbackup", file.Filename)
	}
	if strings.Contains(string(file.Content), "Production") || strings.Contains(string(file.Content), "database/password") {
		t.Fatalf("backup content leaked plaintext data: %s", string(file.Content))
	}
	var envelope encryptedDocument
	if err := json.Unmarshal(file.Content, &envelope); err != nil {
		t.Fatalf("backup envelope json error = %v", err)
	}
	if envelope.KDF != "pbkdf2-sha256" {
		t.Fatalf("KDF = %q, want pbkdf2-sha256", envelope.KDF)
	}
	if envelope.Salt == "" {
		t.Fatalf("Salt is empty")
	}
	if envelope.Iterations < 200000 {
		t.Fatalf("Iterations = %d, want at least 200000", envelope.Iterations)
	}

	target := testDB(t)
	testOwner(t, target, testOwnerID)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), testOwnerID, file.Content, "backup-pass"); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	var vaultName string
	if err := target.QueryRow(`SELECT name FROM vaults WHERE id = 'vault-1'`).Scan(&vaultName); err != nil {
		t.Fatalf("restored vault missing: %v", err)
	}
	if vaultName != "Production" {
		t.Fatalf("restored vault name = %q", vaultName)
	}
	var entryPath string
	if err := target.QueryRow(`SELECT path FROM entries WHERE id = 'entry-1'`).Scan(&entryPath); err != nil {
		t.Fatalf("restored entry missing: %v", err)
	}
	if entryPath != "database/password" {
		t.Fatalf("restored entry path = %q", entryPath)
	}
	// The restored rows belong to the restoring user, whatever the snapshot said.
	var owner string
	if err := target.QueryRow(`SELECT owner_id FROM vaults WHERE id = 'vault-1'`).Scan(&owner); err != nil {
		t.Fatalf("restored vault owner: %v", err)
	}
	if owner != testOwnerID {
		t.Fatalf("restored vault owner = %q, want %q", owner, testOwnerID)
	}
}

// A snapshot imported by user A must never land in user B's account: Restore
// forces owner_id to the restoring user and only clears that user's rows.
func TestRestoreIsScopedToTheRestoringUser(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)
	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), testOwnerID, "backup-pass")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	target := testDB(t)
	testOwner(t, target, testOwnerID)
	// A second account with its own data on the target.
	testOwner(t, target, "other-user")
	if _, err := target.Exec(`INSERT INTO vaults(id, owner_id, name, description, created_at, updated_at)
		VALUES('other-vault', 'other-user', 'Other data', '', '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z')`); err != nil {
		t.Fatalf("insert other user's vault: %v", err)
	}

	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), testOwnerID, file.Content, "backup-pass"); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	var otherVaults int
	if err := target.QueryRow(`SELECT COUNT(*) FROM vaults WHERE owner_id = 'other-user'`).Scan(&otherVaults); err != nil {
		t.Fatalf("count other vaults: %v", err)
	}
	if otherVaults != 1 {
		t.Fatalf("other user's vaults after restore = %d, want 1 (their data must survive)", otherVaults)
	}
}

func TestRestoreRejectsWrongPassword(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), testOwnerID, "right-pass")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	target := testDB(t)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), testOwnerID, file.Content, "wrong-pass"); err == nil {
		t.Fatalf("Restore() with wrong password succeeded")
	}
}

func TestRestoreSupportsLegacySHA256Envelope(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	doc, err := service.collect(context.Background(), testOwnerID)
	if err != nil {
		t.Fatalf("collect() error = %v", err)
	}
	plaintext, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	ciphertext, err := legacyEncryptForTest("legacy-pass", string(plaintext))
	if err != nil {
		t.Fatalf("legacyEncryptForTest() error = %v", err)
	}
	legacy, err := json.Marshal(encryptedDocument{
		Format:     FormatVersion,
		Version:    1,
		CreatedAt:  "2026-06-07T00:00:00Z",
		Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatalf("Marshal legacy envelope error = %v", err)
	}

	target := testDB(t)
	testOwner(t, target, testOwnerID)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), testOwnerID, legacy, "legacy-pass"); err != nil {
		t.Fatalf("Restore() legacy error = %v", err)
	}
}

func TestExportUsesAppSecretWhenPasswordIsEmpty(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), testOwnerID, "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	target := testDB(t)
	testOwner(t, target, testOwnerID)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), testOwnerID, file.Content, ""); err != nil {
		t.Fatalf("Restore() with app secret error = %v", err)
	}
}

func TestClearHistoryRemovesBackupRecordsOnly(t *testing.T) {
	database := testDB(t)
	insertSampleData(t, database)

	service := New(database, "app-secret")
	if _, err := service.Export(context.Background(), testOwnerID, "backup-pass"); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if err := service.ClearHistory(context.Background(), testOwnerID); err != nil {
		t.Fatalf("ClearHistory() error = %v", err)
	}

	var backupCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM backups`).Scan(&backupCount); err != nil {
		t.Fatalf("backup count query: %v", err)
	}
	if backupCount != 0 {
		t.Fatalf("backup count = %d, want 0", backupCount)
	}
	var vaultCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM vaults`).Scan(&vaultCount); err != nil {
		t.Fatalf("vault count query: %v", err)
	}
	if vaultCount != 1 {
		t.Fatalf("vault count = %d, want 1", vaultCount)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	return opdb.OpenTest(t)
}

// testOwner inserts the account the sample rows belong to.
func testOwner(t *testing.T, database *sql.DB, id string) string {
	t.Helper()
	_, err := database.Exec(`INSERT INTO users(id, email, password_hash, role, status, must_change_password, created_at, updated_at)
		VALUES($1, $2, 'argon2id$test', 'user', 'active', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		id, id+"@test.local",
	)
	if err != nil {
		t.Fatalf("insert test owner: %v", err)
	}
	return id
}

func insertSampleData(t *testing.T, database *sql.DB) {
	t.Helper()
	testOwner(t, database, testOwnerID)
	_, err := database.Exec(`
INSERT INTO api_keys(id, owner_id, name, key_prefix, key_hash, key_suffix, encrypted_token, permissions, rate_limit_rpm, is_active, created_at, updated_at)
VALUES('key-1', 'owner-1', 'Agent', 'op_live_abcd1234', 'hash', '1234', 'cipher-token', '{"vaults:read":true}', 60, 1, '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z');
INSERT INTO vaults(id, owner_id, name, description, created_at, updated_at) VALUES('vault-1', 'owner-1', 'Production', 'Prod secrets', '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z');
INSERT INTO entries(id, vault_id, path, type, encrypted_value, tags, created_at, updated_at) VALUES('entry-1', 'vault-1', 'database/password', 'password', 'cipher-value', '["database"]', '2026-01-02T03:04:05Z', '2026-01-02T03:04:05Z');
INSERT INTO api_audit_logs(id, api_key_id, owner_id, key_prefix, method, endpoint, request_id, status_code, duration_ms, result, created_at)
VALUES('log-1', 'key-1', 'owner-1', 'op_live_abcd1234', 'GET', '/api/v1/vaults', 'request-1', 200, 3, 'success', '2026-01-02T03:04:05Z');
`)
	if err != nil {
		t.Fatalf("insert sample data: %v", err)
	}
}

func legacyEncryptForTest(password, plaintext string) (string, error) {
	box := secure.NewBox(password)
	return box.EncryptString(plaintext)
}
