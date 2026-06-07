package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesDefaultsAndPersistsGeneratedSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENPASS_ADDR", "")
	t.Setenv("OPENPASS_DB_PATH", filepath.Join(dir, "openpass.db"))
	t.Setenv("OPENPASS_SECRET_FILE", filepath.Join(dir, "openpass.secret"))
	t.Setenv("OPENPASS_SECRET_KEY", "")
	t.Setenv("OPENPASS_ADMIN_PASSWORD", "admin-pass")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", cfg.Addr)
	}
	if cfg.AdminPassword != "admin-pass" {
		t.Fatalf("AdminPassword not loaded")
	}
	if len(cfg.SecretKey) < 32 {
		t.Fatalf("SecretKey too short: %d", len(cfg.SecretKey))
	}
	if _, err := os.Stat(cfg.SecretFile); err != nil {
		t.Fatalf("secret file was not written: %v", err)
	}

	cfg2, err := Load()
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if cfg2.SecretKey != cfg.SecretKey {
		t.Fatalf("secret key changed between loads")
	}
}

func TestLoadGeneratesTemporaryAdminPasswordWhenMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENPASS_DB_PATH", filepath.Join(dir, "openpass.db"))
	t.Setenv("OPENPASS_SECRET_FILE", filepath.Join(dir, "openpass.secret"))
	t.Setenv("OPENPASS_SECRET_KEY", "local-secret")
	t.Setenv("OPENPASS_ADMIN_PASSWORD", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.GeneratedAdminPassword {
		t.Fatalf("GeneratedAdminPassword = false, want true")
	}
	if len(cfg.AdminPassword) < 16 {
		t.Fatalf("generated admin password too short")
	}
}
