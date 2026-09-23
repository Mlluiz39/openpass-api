package secure

import (
	"regexp"
	"testing"
)

func TestGenerateAPIKeyShapePrefixSuffixAndHash(t *testing.T) {
	key, err := GenerateAPIKey("live")
	if err != nil {
		t.Fatalf("GenerateAPIKey() error = %v", err)
	}
	if !regexp.MustCompile(`^op_live_[0-9a-f]{48}$`).MatchString(key.Plaintext) {
		t.Fatalf("unexpected key format: %q", key.Plaintext)
	}
	if key.Prefix != key.Plaintext[:16] {
		t.Fatalf("Prefix = %q, want first 16 chars", key.Prefix)
	}
	if key.Suffix != key.Plaintext[len(key.Plaintext)-4:] {
		t.Fatalf("Suffix = %q, want last 4 chars", key.Suffix)
	}
	if len(key.Hash) != 64 {
		t.Fatalf("Hash length = %d, want 64", len(key.Hash))
	}
	if !VerifySHA256(key.Plaintext, key.Hash) {
		t.Fatalf("VerifySHA256 rejected generated hash")
	}
	if VerifySHA256(key.Plaintext+"x", key.Hash) {
		t.Fatalf("VerifySHA256 accepted wrong token")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	box := NewBox("test-secret")
	ciphertext, err := box.EncryptString("super secret")
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}
	if ciphertext == "" || ciphertext == "super secret" {
		t.Fatalf("ciphertext was not encrypted: %q", ciphertext)
	}
	plaintext, err := box.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}
	if plaintext != "super secret" {
		t.Fatalf("DecryptString() = %q", plaintext)
	}
}

func TestExtractPrefixRejectsInvalidKeys(t *testing.T) {
	if got := ExtractPrefix("op_live_12345678abcdef"); got != "op_live_12345678" {
		t.Fatalf("ExtractPrefix() = %q", got)
	}
	if got := ExtractPrefix("bad"); got != "" {
		t.Fatalf("ExtractPrefix(bad) = %q, want empty", got)
	}
	if got := ExtractPrefix("2d6c7d1f723f704066c899ccc1e177d81ef88cbd84558e5e"); got != "2d6c7d1f723f7040" {
		t.Fatalf("ExtractPrefix(hex) = %q, want first 16 chars", got)
	}
	if got := ExtractPrefix("1234567890"); got != "1234567890" {
		t.Fatalf("ExtractPrefix(10 chars) = %q, want full token", got)
	}
}

func TestGenerateAPIKeyWithoutPrefix(t *testing.T) {
	for _, env := range []string{"", "none", "raw"} {
		key, err := GenerateAPIKey(env)
		if err != nil {
			t.Fatalf("GenerateAPIKey(%q) error = %v", env, err)
		}
		if !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(key.Plaintext) {
			t.Fatalf("expected pure hex token without prefix for env %q: %q", env, key.Plaintext)
		}
		if key.Prefix != key.Plaintext[:16] {
			t.Fatalf("Prefix = %q, want %q", key.Prefix, key.Plaintext[:16])
		}
		if key.Suffix != key.Plaintext[len(key.Plaintext)-4:] {
			t.Fatalf("Suffix = %q, want last 4 chars", key.Suffix)
		}
		if !VerifySHA256(key.Plaintext, key.Hash) {
			t.Fatalf("VerifySHA256 failed for pure hex key")
		}
	}
}

func TestNewAPIKeyCustomToken(t *testing.T) {
	token := "my-custom-api-token-secret-123"
	key, err := NewAPIKey(token)
	if err != nil {
		t.Fatalf("NewAPIKey() error = %v", err)
	}
	if key.Plaintext != token {
		t.Fatalf("Plaintext = %q, want %q", key.Plaintext, token)
	}
	if key.Prefix != token[:16] {
		t.Fatalf("Prefix = %q, want %q", key.Prefix, token[:16])
	}
	if key.Suffix != "secret-123"[len("secret-123")-4:] {
		t.Fatalf("Suffix = %q, want last 4 chars", key.Suffix)
	}
	if !VerifySHA256(token, key.Hash) {
		t.Fatalf("VerifySHA256 failed for custom token")
	}

	_, err = NewAPIKey("short")
	if err == nil {
		t.Fatalf("expected error for token < 8 chars")
	}
}
