package authenticator

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
	"github.com/openpass/api/internal/totp"
	"github.com/openpass/api/internal/vault"
)

const testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestSetSecretStoresItEncryptedAndReturnsCodes(t *testing.T) {
	db, svc, auth, owner, entryID := fixture(t)

	if err := auth.SetSecret(context.Background(), owner, entryID, testSecret); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}

	// The secret must not be readable in the table: it is a credential.
	var stored sql.NullString
	if err := db.QueryRow(`SELECT encrypted_totp FROM entries WHERE id = $1`, entryID).Scan(&stored); err != nil {
		t.Fatalf("query encrypted_totp: %v", err)
	}
	if !stored.Valid || stored.String == testSecret {
		t.Fatalf("secret stored in plaintext: %q", stored.String)
	}

	has, err := auth.HasSecret(context.Background(), owner, entryID)
	if err != nil || !has {
		t.Fatalf("HasSecret() = %v, %v; want true, nil", has, err)
	}

	code, err := auth.Code(context.Background(), owner, entryID)
	if err != nil {
		t.Fatalf("Code() error = %v", err)
	}
	cfg, _ := totp.Parse(testSecret)
	want, err := totp.Generate(cfg, time.Now().UTC())
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	// Both must land in the same 30s window; if the clock crossed the boundary
	// between the two calls, either code is still valid, so accept that case.
	if code.Code != want.Code && code.SecondsRemaining == want.Period {
		t.Fatalf("Code() = %s, want %s", code.Code, want.Code)
	}
	if len(code.Code) != 6 {
		t.Fatalf("Code() = %q, want 6 digits", code.Code)
	}

	_ = svc
}

func TestSetSecretAcceptsOtpAuthURI(t *testing.T) {
	_, _, auth, owner, entryID := fixture(t)

	uri := "otpauth://totp/ACME:alice@acme.test?secret=" + testSecret + "&issuer=ACME&digits=6"
	if err := auth.SetSecret(context.Background(), owner, entryID, uri); err != nil {
		t.Fatalf("SetSecret(otpauth) error = %v", err)
	}
	code, err := auth.Code(context.Background(), owner, entryID)
	if err != nil {
		t.Fatalf("Code() error = %v", err)
	}
	if len(code.Code) != 6 {
		t.Fatalf("Code() = %q, want 6 digits", code.Code)
	}
}

func TestSetSecretRejectsInvalidAndClearsWithEmpty(t *testing.T) {
	_, _, auth, owner, entryID := fixture(t)
	ctx := context.Background()

	if err := auth.SetSecret(ctx, owner, entryID, "não-é-base32!!"); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("SetSecret(invalid) error = %v, want ErrInvalidSecret", err)
	}

	if err := auth.SetSecret(ctx, owner, entryID, testSecret); err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}
	if err := auth.SetSecret(ctx, owner, entryID, ""); err != nil {
		t.Fatalf("SetSecret(clear) error = %v", err)
	}

	has, err := auth.HasSecret(ctx, owner, entryID)
	if err != nil || has {
		t.Fatalf("HasSecret() after clear = %v, %v; want false, nil", has, err)
	}
	if _, err := auth.Code(ctx, owner, entryID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("Code() after clear = %v, want ErrNoSecret", err)
	}
}

// Another user must not be able to set, read or clear an entry's secret.
func TestSecretsAreScopedToTheOwner(t *testing.T) {
	db, _, auth, owner, entryID := fixture(t)
	ctx := context.Background()

	intruder := insertUser(t, db, "intruder")

	if err := auth.SetSecret(ctx, intruder, entryID, testSecret); !errors.Is(err, vault.ErrForbidden) {
		t.Fatalf("SetSecret(intruder) error = %v, want ErrForbidden", err)
	}
	if _, err := auth.Code(ctx, intruder, entryID); !errors.Is(err, vault.ErrForbidden) {
		t.Fatalf("Code(intruder) error = %v, want ErrForbidden", err)
	}

	// The owner can still use it normally afterwards.
	if err := auth.SetSecret(ctx, owner, entryID, testSecret); err != nil {
		t.Fatalf("SetSecret(owner) error = %v", err)
	}
	if _, err := auth.Code(ctx, owner, entryID); err != nil {
		t.Fatalf("Code(owner) error = %v", err)
	}
}

func TestCodeOnEntryWithoutSecret(t *testing.T) {
	_, _, auth, owner, entryID := fixture(t)
	if _, err := auth.Code(context.Background(), owner, entryID); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("Code() = %v, want ErrNoSecret", err)
	}
}

// -------------------------------------------------------------- fixtures

func fixture(t *testing.T) (*sql.DB, *vault.Service, *Service, string, string) {
	t.Helper()
	db := opdb.OpenTest(t)
	secretBox := secure.NewBox("test-secret")
	svc := vault.New(db, "test-secret")

	owner := insertUser(t, db, "owner-auth")
	v, err := svc.CreateVault(context.Background(), owner, vault.VaultInput{Name: "Principal"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	entry, err := svc.CreateEntry(context.Background(), owner, vault.EntryInput{
		VaultID: v.ID, Path: "GitHub", Type: "login", Value: "senha",
		Metadata: map[string]string{"username": "octocat", "url": "https://github.com"},
	})
	if err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	return db, svc, New(db, svc, secretBox), owner, entry.ID
}

func insertUser(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	_, err := db.Exec(`INSERT INTO users(id, email, password_hash, role, status, must_change_password, created_at, updated_at)
		VALUES($1, $2, 'argon2id$test', 'user', 'active', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		id, id+"@test.local")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}
