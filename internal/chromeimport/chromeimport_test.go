package chromeimport

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/vault"
)

// sampleCSV mirrors the file Chrome's password manager exports, including the
// UTF-8 BOM Chrome writes and a row with an empty password.
const sampleCSV = "\ufeffname,url,username,password,note\n" +
	"GitHub,https://github.com,octocat,s3cr3t!,work account\n" +
	"Sem senha,https://example.com,vazio,,\n" +
	"Gmail,https://accounts.google.com,me@gmail.com,outra-senha,\n"

func TestImportCreatesLoginEntries(t *testing.T) {
	database := testDB(t)
	svc := vault.New(database, "secret")
	owner := testOwner(t, database, "owner-chrome")

	res, err := Import(context.Background(), svc, owner, sampleCSV, Options{})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if res.Imported != 2 {
		t.Fatalf("Imported = %d, want 2 (the empty-password row must be skipped)", res.Imported)
	}
	if res.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", res.Skipped)
	}
	if res.VaultName != "Principal" {
		t.Fatalf("VaultName = %q, want Principal", res.VaultName)
	}

	entries, err := svc.ListEntries(context.Background(), owner, res.VaultID)
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	byName := map[string]vault.Entry{}
	for _, e := range entries {
		byName[e.Path] = e
	}
	github, ok := byName["GitHub"]
	if !ok {
		t.Fatalf("entry GitHub not found; got %v", res.Names)
	}
	if github.Type != "login" {
		t.Fatalf("GitHub type = %q, want login", github.Type)
	}
	if github.Metadata["username"] != "octocat" {
		t.Fatalf("GitHub username = %q, want octocat", github.Metadata["username"])
	}

	// The value must round-trip through the vault's encryption.
	revealed, err := svc.RevealEntry(context.Background(), owner, github.ID)
	if err != nil {
		t.Fatalf("RevealEntry() error = %v", err)
	}
	if revealed != "s3cr3t!" {
		t.Fatalf("RevealEntry() = %q, want s3cr3t!", revealed)
	}
}

func TestImportIsIdempotentAndNeverOverwrites(t *testing.T) {
	database := testDB(t)
	svc := vault.New(database, "secret")
	owner := testOwner(t, database, "owner-chrome-2")

	first, err := Import(context.Background(), svc, owner, sampleCSV, Options{})
	if err != nil {
		t.Fatalf("first Import() error = %v", err)
	}
	second, err := Import(context.Background(), svc, owner, sampleCSV, Options{})
	if err != nil {
		t.Fatalf("second Import() error = %v", err)
	}
	if second.Imported != 0 {
		t.Fatalf("second Import() imported %d, want 0", second.Imported)
	}
	if second.Skipped != 3 {
		t.Fatalf("second Import() skipped %d, want 3", second.Skipped)
	}
	if first.VaultID != second.VaultID {
		t.Fatalf("vault was recreated: %q vs %q", first.VaultID, second.VaultID)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	database := testDB(t)
	svc := vault.New(database, "secret")
	owner := testOwner(t, database, "owner-chrome-3")

	res, err := Import(context.Background(), svc, owner, sampleCSV, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Import(dry-run) error = %v", err)
	}
	if !res.DryRun || res.Imported != 2 {
		t.Fatalf("dry run reported imported=%d dry_run=%v, want 2/true", res.Imported, res.DryRun)
	}

	vaults, err := svc.ListVaults(context.Background(), owner, nil)
	if err != nil {
		t.Fatalf("ListVaults() error = %v", err)
	}
	if len(vaults) != 0 {
		t.Fatalf("dry run created %d vault(s), want 0", len(vaults))
	}
}

func TestCustomVaultName(t *testing.T) {
	database := testDB(t)
	svc := vault.New(database, "secret")
	owner := testOwner(t, database, "owner-chrome-4")

	res, err := Import(context.Background(), svc, owner, sampleCSV, Options{VaultName: "Chrome"})
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if res.VaultName != "Chrome" {
		t.Fatalf("VaultName = %q, want Chrome", res.VaultName)
	}
	vaults, err := svc.ListVaults(context.Background(), owner, nil)
	if err != nil {
		t.Fatalf("ListVaults() error = %v", err)
	}
	if len(vaults) != 1 || vaults[0].Name != "Chrome" {
		t.Fatalf("vaults = %+v, want a single vault named Chrome", vaults)
	}
}

func TestMissingPasswordColumnIsRejected(t *testing.T) {
	database := testDB(t)
	svc := vault.New(database, "secret")
	owner := testOwner(t, database, "owner-chrome-5")

	_, err := Import(context.Background(), svc, owner, "name,url\nFoo,https://foo.test\n", Options{})
	if err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("Import() error = %v, want a complaint about the password column", err)
	}
}

func TestHostOfStripsSchemeAndWWW(t *testing.T) {
	cases := map[string]string{
		"https://www.example.com/login": "example.com",
		"example.com":                   "example.com",
		"":                              "",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	return opdb.OpenTest(t)
}

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
