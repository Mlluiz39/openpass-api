package bwcrypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCipherStringRoundTrip(t *testing.T) {
	masterKey, err := DeriveMasterKey("correct horse battery staple", NormalizeSalt("User@Example.com"), DefaultKDF())
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	key := StretchKey(masterKey)
	if len(key) != 64 {
		t.Fatalf("StretchKey len = %d, want 64", len(key))
	}

	plaintext := "senha-super-secreta-çãõ"
	encoded, err := Encrypt(key, []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(encoded, "2.") {
		t.Fatalf("Encrypt prefix = %q, want 2.", encoded[:2])
	}
	decoded, err := DecryptString(key, encoded)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if decoded != plaintext {
		t.Fatalf("round trip = %q, want %q", decoded, plaintext)
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	masterKey, err := DeriveMasterKey("pw", NormalizeSalt("a@b.c"), DefaultKDF())
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	key := StretchKey(masterKey)
	encoded, err := Encrypt(key, []byte("value"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	parts := strings.Split(encoded, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	raw[0] ^= 0xff
	tampered := "2." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[3]
	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatal("Decrypt(tampered) succeeded, want authentication failure")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	keyA := StretchKey([]byte("key-a"))
	keyB := StretchKey([]byte("key-b"))
	encoded, err := Encrypt(keyA, []byte("value"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(keyB, encoded); err == nil {
		t.Fatal("Decrypt(wrong key) succeeded, want failure")
	}
}

func TestUserKeyWrapRoundTrip(t *testing.T) {
	salt := NormalizeSalt("user@example.com")
	masterKey, err := DeriveMasterKey("pw", salt, DefaultKDF())
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	userKey, err := GenerateUserKey()
	if err != nil {
		t.Fatalf("GenerateUserKey: %v", err)
	}
	wrapped, err := WrapUserKey(masterKey, userKey)
	if err != nil {
		t.Fatalf("WrapUserKey: %v", err)
	}
	unwrapped, err := UnwrapUserKey(masterKey, wrapped)
	if err != nil {
		t.Fatalf("UnwrapUserKey: %v", err)
	}
	if string(unwrapped) != string(userKey) {
		t.Fatal("unwrapped user key differs from the original")
	}

	otherKey, _ := DeriveMasterKey("wrong", salt, DefaultKDF())
	if _, err := UnwrapUserKey(otherKey, wrapped); err == nil {
		t.Fatal("UnwrapUserKey with wrong master key succeeded, want failure")
	}
}

func TestMasterKeyVerification(t *testing.T) {
	salt := NormalizeSalt("user@example.com")
	masterKey, err := DeriveMasterKey("pw", salt, DefaultKDF())
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	stored := HashMasterKey(masterKey, salt)
	if !VerifyMasterKey(masterKey, salt, stored) {
		t.Fatal("VerifyMasterKey rejected the correct master key")
	}
	wrongKey, _ := DeriveMasterKey("other", salt, DefaultKDF())
	if VerifyMasterKey(wrongKey, salt, stored) {
		t.Fatal("VerifyMasterKey accepted a wrong master key")
	}
	if VerifyMasterKey(masterKey, salt, "not-base64!!") {
		t.Fatal("VerifyMasterKey accepted a malformed stored hash")
	}
}

func TestArgon2idDerivation(t *testing.T) {
	kdf := KdfParams{Type: KdfArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 4}
	if err := kdf.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	key, err := DeriveMasterKey("pw", NormalizeSalt("a@b.c"), kdf)
	if err != nil {
		t.Fatalf("DeriveMasterKey(argon2): %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("argon2 key len = %d, want 32", len(key))
	}
}

func TestKdfValidation(t *testing.T) {
	cases := []struct {
		kdf KdfParams
		ok  bool
	}{
		{DefaultKDF(), true},
		{KdfParams{Type: KdfPBKDF2SHA256, Iterations: 5000}, false},
		{KdfParams{Type: KdfArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 4}, true},
		{KdfParams{Type: KdfArgon2id, Iterations: 3, MemoryMB: 2048, Parallelism: 4}, false},
		{KdfParams{Type: KdfArgon2id, Iterations: 3, MemoryMB: 64, Parallelism: 32}, false},
		{KdfParams{Type: 99}, false},
	}
	for _, tc := range cases {
		if err := tc.kdf.Validate(); (err == nil) != tc.ok {
			t.Fatalf("Validate(%+v) ok = %v, want %v", tc.kdf, err == nil, tc.ok)
		}
	}
}

func TestGenerateKeyPairFormats(t *testing.T) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) == 0 {
		t.Fatalf("public key is not base64 DER: %v", err)
	}
	priv, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(priv) == 0 {
		t.Fatalf("private key is not base64 DER: %v", err)
	}
	// The private key must be encryptable/decryptable with the user key.
	userKey, _ := GenerateUserKey()
	encrypted, err := EncryptPrivateKey(userKey, privateKey)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	decrypted, err := DecryptString(userKey, encrypted)
	if err != nil {
		t.Fatalf("DecryptString(private key): %v", err)
	}
	if decrypted != string(priv) {
		t.Fatal("private key changed through wrap/unwrap")
	}
}
