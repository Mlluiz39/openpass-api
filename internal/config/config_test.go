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

func TestLoadParsesResetFlag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENPASS_DB_PATH", filepath.Join(dir, "openpass.db"))
	t.Setenv("OPENPASS_SECRET_FILE", filepath.Join(dir, "openpass.secret"))
	t.Setenv("OPENPASS_SECRET_KEY", "local-secret")
	t.Setenv("OPENPASS_ADMIN_PASSWORD", "admin-pass")
	t.Setenv("OPENPASS_ADMIN_PASSWORD_RESET", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.ResetAdminPassword {
		t.Fatalf("ResetAdminPassword = false, want true for \"true\"")
	}

	for _, value := range []string{"1", "TRUE", "yes", "on"} {
		t.Setenv("OPENPASS_ADMIN_PASSWORD_RESET", value)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() with %q error = %v", value, err)
		}
		if !cfg.ResetAdminPassword {
			t.Fatalf("ResetAdminPassword = false for %q, want true", value)
		}
	}

	t.Setenv("OPENPASS_ADMIN_PASSWORD_RESET", "0")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ResetAdminPassword {
		t.Fatalf("ResetAdminPassword = true for \"0\", want false")
	}
}

func TestLoadRejectsResetWithoutPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENPASS_DB_PATH", filepath.Join(dir, "openpass.db"))
	t.Setenv("OPENPASS_SECRET_FILE", filepath.Join(dir, "openpass.secret"))
	t.Setenv("OPENPASS_SECRET_KEY", "local-secret")
	t.Setenv("OPENPASS_ADMIN_PASSWORD", "")
	t.Setenv("OPENPASS_ADMIN_PASSWORD_RESET", "1")

	if _, err := Load(); err == nil {
		t.Fatalf("Load() error = nil, want error when reset is set without a password")
	}
}
