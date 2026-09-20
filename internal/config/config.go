package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Addr                   string
	DatabasePath           string
	SecretFile             string
	SecretKey              string
	AdminPassword          string
	GeneratedAdminPassword bool
}

func Load() (Config, error) {
	cfg := Config{
		Addr:         envOr("OPENPASS_ADDR", ":8080"),
		DatabasePath: envOr("OPENPASS_DB_PATH", filepath.Join("data", "openpass.db")),
		SecretFile:   envOr("OPENPASS_SECRET_FILE", filepath.Join("data", "openpass.secret")),
		SecretKey:    strings.TrimSpace(os.Getenv("OPENPASS_SECRET_KEY")),
	}

	if cfg.SecretKey == "" {
		key, err := loadOrCreateSecret(cfg.SecretFile)
		if err != nil {
			return Config{}, err
		}
		cfg.SecretKey = key
	}

	cfg.AdminPassword = strings.TrimSpace(os.Getenv("OPENPASS_ADMIN_PASSWORD"))
	if cfg.AdminPassword == "" {
		password, err := randomHex(12)
		if err != nil {
			return Config{}, err
		}
		cfg.AdminPassword = password
		cfg.GeneratedAdminPassword = true
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func loadOrCreateSecret(path string) (string, error) {
	if content, err := os.ReadFile(path); err == nil {
		value := strings.TrimSpace(string(content))
		if value != "" {
			return value, nil
		}
	}

	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
