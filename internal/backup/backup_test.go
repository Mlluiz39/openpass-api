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

func TestExportIsEncryptedAndRestoreRecoversData(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), "backup-pass")
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
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), file.Content, "backup-pass"); err != nil {
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
}

func TestRestoreRejectsWrongPassword(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), "right-pass")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	target := testDB(t)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), file.Content, "wrong-pass"); err == nil {
		t.Fatalf("Restore() with wrong password succeeded")
	}
}

func TestRestoreSupportsLegacySHA256Envelope(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	doc, err := service.collect(context.Background())
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
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), legacy, "legacy-pass"); err != nil {
		t.Fatalf("Restore() legacy error = %v", err)
	}
}

func TestExportUsesAppSecretWhenPasswordIsEmpty(t *testing.T) {
	source := testDB(t)
	insertSampleData(t, source)

	service := New(source, "app-secret")
	file, err := service.Export(context.Background(), "")
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	target := testDB(t)
	restoreService := New(target, "app-secret")
	if err := restoreService.Restore(context.Background(), file.Content, ""); err != nil {
		t.Fatalf("Restore() with app secret error = %v", err)
	}
}

func TestClearHistoryRemovesBackupRecordsOnly(t *testing.T) {
	database := testDB(t)
	insertSampleData(t, database)

	service := New(database, "app-secret")
	if _, err := service.Export(context.Background(), "backup-pass"); err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if err := service.ClearHistory(context.Background()); err != nil {
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
	database, err := opdb.Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := opdb.Migrate(database, opdb.CoreSchema); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}

func insertSampleData(t *testing.T, database *sql.DB) {
	t.Helper()
	_, err := database.Exec(`
INSERT INTO api_keys(id, name, key_prefix, key_hash, key_suffix, encrypted_token, permissions, rate_limit_rpm, is_active)
VALUES('key-1', 'Agent', 'op_live_abcd1234', 'hash', '1234', 'cipher-token', '{"vaults:read":true}', 60, 1);
INSERT INTO vaults(id, name, description) VALUES('vault-1', 'Production', 'Prod secrets');
INSERT INTO entries(id, vault_id, path, type, encrypted_value, tags) VALUES('entry-1', 'vault-1', 'database/password', 'password', 'cipher-value', '["database"]');
INSERT INTO api_audit_logs(id, api_key_id, key_prefix, method, endpoint, request_id, status_code, duration_ms, result)
VALUES('log-1', 'key-1', 'op_live_abcd1234', 'GET', '/api/v1/vaults', 'request-1', 200, 3, 'success');
`)
	if err != nil {
		t.Fatalf("insert sample data: %v", err)
	}
}

func legacyEncryptForTest(password, plaintext string) (string, error) {
	box := secure.NewBox(password)
	return box.EncryptString(plaintext)
}
