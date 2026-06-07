package vault

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openpass/api/internal/apikeys"
	opdb "github.com/openpass/api/internal/db"
)

func TestCreateEntryStoresEncryptedValueAndRevealDecryptsIt(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	v, err := service.CreateVault(context.Background(), VaultInput{Name: "Production"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	entry, err := service.CreateEntry(context.Background(), EntryInput{
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
	if err := database.QueryRow(`SELECT encrypted_value FROM entries WHERE id = ?`, entry.ID).Scan(&encrypted); err != nil {
		t.Fatalf("query entry: %v", err)
	}
	if encrypted == "super-secret" {
		t.Fatalf("secret stored in plaintext")
	}

	revealed, err := service.RevealEntry(context.Background(), entry.ID)
	if err != nil {
		t.Fatalf("RevealEntry() error = %v", err)
	}
	if revealed != "super-secret" {
		t.Fatalf("RevealEntry() = %q, want super-secret", revealed)
	}
}

func TestListEntriesForAPIRespectsVaultScope(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	v1, err := service.CreateVault(context.Background(), VaultInput{Name: "Allowed"})
	if err != nil {
		t.Fatalf("CreateVault(v1) error = %v", err)
	}
	v2, err := service.CreateVault(context.Background(), VaultInput{Name: "Blocked"})
	if err != nil {
		t.Fatalf("CreateVault(v2) error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), EntryInput{VaultID: v1.ID, Path: "ok", Type: "password", Value: "one"}); err != nil {
		t.Fatalf("CreateEntry(v1) error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), EntryInput{VaultID: v2.ID, Path: "no", Type: "password", Value: "two"}); err != nil {
		t.Fatalf("CreateEntry(v2) error = %v", err)
	}

	key := &apikeys.AuthenticatedKey{VaultScope: []string{v1.ID}, Permissions: map[string]bool{"entries:read": true}}
	entries, err := service.ListEntriesForAPI(context.Background(), key, v1.ID)
	if err != nil {
		t.Fatalf("ListEntriesForAPI(v1) error = %v", err)
	}
	if len(entries) != 1 || entries[0].VaultID != v1.ID {
		t.Fatalf("entries = %+v, want one entry from v1", entries)
	}

	_, err = service.ListEntriesForAPI(context.Background(), key, v2.ID)
	if err != ErrForbidden {
		t.Fatalf("ListEntriesForAPI(v2) err = %v, want ErrForbidden", err)
	}
}

func TestUpdateAndDeleteVault(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	v, err := service.CreateVault(context.Background(), VaultInput{Name: "Old", Description: "before"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if _, err := service.CreateEntry(context.Background(), EntryInput{VaultID: v.ID, Path: "secret", Type: "password", Value: "value"}); err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	updated, err := service.UpdateVault(context.Background(), v.ID, VaultInput{Name: "New", Description: "after"})
	if err != nil {
		t.Fatalf("UpdateVault() error = %v", err)
	}
	if updated.Name != "New" || updated.Description != "after" {
		t.Fatalf("updated vault = %+v", updated)
	}

	if err := service.DeleteVault(context.Background(), v.ID); err != nil {
		t.Fatalf("DeleteVault() error = %v", err)
	}
	if _, err := service.getVault(context.Background(), v.ID); err != sql.ErrNoRows {
		t.Fatalf("getVault() after delete err = %v, want sql.ErrNoRows", err)
	}
	entries, err := service.ListEntries(context.Background(), v.ID)
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after vault delete = %d, want 0", len(entries))
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
