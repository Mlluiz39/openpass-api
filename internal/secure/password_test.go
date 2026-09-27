package secure

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "argon2id$v=") {
		t.Fatalf("hash = %q, want argon2id PHC format", hash)
	}

	if ok, rehash := VerifyPassword("correct horse battery staple", hash); !ok || rehash {
		t.Fatalf("VerifyPassword() = (%v, %v), want (true, false)", ok, rehash)
	}
	if ok, _ := VerifyPassword("wrong", hash); ok {
		t.Fatalf("VerifyPassword() accepted wrong password")
	}
}

// Two hashes of the same password must differ (fresh random salt) and both
// must verify.
func TestHashPasswordUsesFreshSalt(t *testing.T) {
	first, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	second, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if first == second {
		t.Fatalf("two hashes are identical, salt is not random")
	}
	if ok, _ := VerifyPassword("same-password", second); !ok {
		t.Fatalf("second hash does not verify")
	}
}

func TestVerifyPasswordAcceptsLegacyAndRequestsRehash(t *testing.T) {
	salt := "0123456789abcdef"
	legacy := BuildLegacyHash(salt, SHA256Hex(salt+":old-panel-pass"))

	if ok, rehash := VerifyPassword("old-panel-pass", legacy); !ok || !rehash {
		t.Fatalf("VerifyPassword(legacy) = (%v, %v), want (true, true)", ok, rehash)
	}
	if ok, _ := VerifyPassword("nope", legacy); ok {
		t.Fatalf("legacy hash accepted wrong password")
	}
}

func TestVerifyPasswordRejectsUnknownFormat(t *testing.T) {
	if ok, rehash := VerifyPassword("x", "plaintext-oops"); ok || rehash {
		t.Fatalf("VerifyPassword(unknown) = (%v, %v), want (false, false)", ok, rehash)
	}
	if ok, _ := VerifyPassword("x", "argon2id$broken"); ok {
		t.Fatalf("malformed argon2id hash accepted")
	}
}
