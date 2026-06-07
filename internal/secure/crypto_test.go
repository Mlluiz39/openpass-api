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
}
