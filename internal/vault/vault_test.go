package vault

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openpass/api/internal/apikeys"
	opdb "github.com/openpass/api/internal/db"
)

func TestCreateEntryStoresEncryptedValueAndRevealDecryptsIt(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	owner := testOwner(t, database, "owner-1")

	v, err := service.CreateVault(context.Background(), owner, VaultInput{Name: "Production"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	entry, err := service.CreateEntry(context.Background(), owner, EntryInput{
		VaultID: v.ID,
		Path:    "database/password",
		Type:    "password",
		Value:   "super-secret",
		Tags:    []string{"database"},
	})
	if err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	var encrypted string
	if err := database.QueryRow(`SELECT encrypted_value FROM entries WHERE id = $1`, entry.ID).Scan(&encrypted); err != nil {
		t.Fatalf("query entry: %v", err)
	}
	if encrypted == "super-secret" {
		t.Fatalf("secret stored in plaintext")
	}

	revealed, err := service.RevealEntry(context.Background(), owner, entry.ID)
	if err != nil {
		t.Fatalf("RevealEntry() error = %v", err)
	}
	if revealed != "super-secret" {
		t.Fatalf("RevealEntry() = %q, want super-secret", revealed)
	}
}

// Total isolation: another user must not see, reveal, update or delete
// someone else's vault or entries — the IDs are known, access still fails.
func TestUsersCannotTouchEachOthersData(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	alice := testOwner(t, database, "alice")
	bob := testOwner(t, database, "bob")

	v, err := service.CreateVault(context.Background(), alice, VaultInput{Name: "Alice vault"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	entry, err := service.CreateEntry(context.Background(), alice, EntryInput{
		VaultID: v.ID, Path: "secret", Type: "password", Value: "alice-secret",
	})
	if err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	vaults, err := service.ListVaults(context.Background(), bob, nil)
	if err != nil {
		t.Fatalf("ListVaults(bob) error = %v", err)
	}
	if len(vaults) != 0 {
		t.Fatalf("bob sees %d vaults, want 0", len(vaults))
	}
	entries, err := service.ListEntries(context.Background(), bob, "")
	if err != nil {
		t.Fatalf("ListEntries(bob) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("bob sees %d entries, want 0", len(entries))
	}
	if _, err := service.RevealEntry(context.Background(), bob, entry.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("RevealEntry(bob) err = %v, want sql.ErrNoRows", err)
	}
	if _, err := service.getEntry(context.Background(), bob, entry.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("getEntry(bob) err = %v, want sql.ErrNoRows", err)
	}
	if err := service.UpdateVault(context.Background(), bob, v.ID, VaultInput{Name: "hijack"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("UpdateVault(bob) err = %v, want sql.ErrNoRows", err)
	}
	if err := service.DeleteEntry(context.Background(), bob, entry.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteEntry(bob) err = %v, want sql.ErrNoRows", err)
	}
	if err := service.DeleteVault(context.Background(), bob, v.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteVault(bob) err = %v, want sql.ErrNoRows", err)
	}
}

func TestListEntriesForAPIRespectsVaultScope(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	owner := testOwner(t, database, "owner-1")

	v1, err := service.CreateVault(context.Background(), owner, VaultInput{Name: "Allowed"})
	if err != nil {
		t.Fatalf("CreateVault(v1) error = %v", err)
	}
	v2, err := service.CreateVault(context.Background(), owner, VaultInput{Name: "Blocked"})
	if err != nil {
		t.Fatalf("CreateVault(v2) error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), owner, EntryInput{VaultID: v1.ID, Path: "ok", Type: "password", Value: "one"}); err != nil {
		t.Fatalf("CreateEntry(v1) error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), owner, EntryInput{VaultID: v2.ID, Path: "no", Type: "password", Value: "two"}); err != nil {
		t.Fatalf("CreateEntry(v2) error = %v", err)
	}

	key := &apikeys.AuthenticatedKey{OwnerID: owner, VaultScope: []string{v1.ID}, Permissions: map[string]bool{"entries:read": true}}
	entries, err := service.ListEntriesForAPI(context.Background(), key, v1.ID)
	if err != nil {
		t.Fatalf("ListEntriesForAPI(v1) error = %v", err)
	}
	if len(entries) != 1 || entries[0].VaultID != v1.ID {
		t.Fatalf("entries = %+v, want one entry from v1", entries)
	}

	// Without a vault filter the scope still limits the result set.
	entries, err = service.ListEntriesForAPI(context.Background(), key, "")
	if err != nil {
		t.Fatalf("ListEntriesForAPI(all) error = %v", err)
	}
	if len(entries) != 1 || entries[0].VaultID != v1.ID {
		t.Fatalf("scoped entries = %+v, want only v1's entry", entries)
	}

	_, err = service.ListEntriesForAPI(context.Background(), key, v2.ID)
	if err != ErrForbidden {
		t.Fatalf("ListEntriesForAPI(v2) err = %v, want ErrForbidden", err)
	}
}

func TestUpdateAndDeleteVault(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	owner := testOwner(t, database, "owner-1")

	v, err := service.CreateVault(context.Background(), owner, VaultInput{Name: "Old", Description: "before"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), owner, EntryInput{VaultID: v.ID, Path: "secret", Type: "password", Value: "value"}); err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	updated, err := service.UpdateVault(context.Background(), owner, v.ID, VaultInput{Name: "New", Description: "after"})
	if err != nil {
		t.Fatalf("UpdateVault() error = %v", err)
	}
	if updated.Name != "New" || updated.Description != "after" {
		t.Fatalf("updated vault = %+v", updated)
	}

	if err := service.DeleteVault(context.Background(), owner, v.ID); err != nil {
		t.Fatalf("DeleteVault() error = %v", err)
	}
	if _, err := service.getVault(context.Background(), owner, v.ID); err != sql.ErrNoRows {
		t.Fatalf("getVault() after delete err = %v, want sql.ErrNoRows", err)
	}
	entries, err := service.ListEntries(context.Background(), owner, v.ID)
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after vault delete = %d, want 0", len(entries))
	}
}

func TestCreateEntryRejectsForeignVault(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	alice := testOwner(t, database, "alice")
	bob := testOwner(t, database, "bob")

	v, err := service.CreateVault(context.Background(), alice, VaultInput{Name: "Alice"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), bob, EntryInput{VaultID: v.ID, Path: "x", Type: "password", Value: "y"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateEntry(bob into alice vault) err = %v, want ErrForbidden", err)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	return opdb.OpenTest(t)
}

// testOwner inserts a minimal user row: vaults.owner_id has a foreign key to
// users, so every vault test needs an account first.
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
