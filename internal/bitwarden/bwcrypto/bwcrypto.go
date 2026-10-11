// Package bwcrypto implements the subset of the Bitwarden client-side
// cryptography this server needs in order to host official Bitwarden
// clients (browser extensions, mobile/desktop apps and the CLI).
//
// All vault data is encrypted *by the clients* with keys the server never
// sees (zero-knowledge). The server-side code here is only used to
// provision an account's key material when the OpenPass panel creates or
// resets a password (it derives exactly what the client would have derived
// from the plaintext it momentarily knows), and to verify the master
// password at login time by comparing hashes.
//
// Format references (upstream Bitwarden):
//   - Master key: PBKDF2-SHA256(password, email, 600000) or Argon2id.
//   - Stretched key: HKDF (zero-salt extract, info "enc") → 64 bytes,
//     first 32 = AES key, last 32 = HMAC key.
//   - CipherString "2.<iv>.<ciphertext>.<mac>": AES-256-CBC + HMAC-SHA256
//     (encrypt-then-MAC over iv||ciphertext), URL-safe base64 without padding.
package bwcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// KDF type constants, matching the upstream enum.
const (
	KdfPBKDF2SHA256 = 0
	KdfArgon2id     = 1
)

// DefaultKDFIterations is the upstream default for PBKDF2-SHA256.
const DefaultKDFIterations = 600000

// KdfParams mirrors the client's key-derivation settings stored per account.
type KdfParams struct {
	Type        int
	Iterations  int
	MemoryMB    int // Argon2id only
	Parallelism int // Argon2id only
}

// DefaultKDF returns the parameters new accounts are provisioned with.
func DefaultKDF() KdfParams {
	return KdfParams{Type: KdfPBKDF2SHA256, Iterations: DefaultKDFIterations}
}

// Validate applies the same bounds upstream enforces on client-supplied KDF
// settings, so a malicious client cannot ask the server to store absurd
// parameters (or too weak ones).
func (k KdfParams) Validate() error {
	switch k.Type {
	case KdfPBKDF2SHA256:
		if k.Iterations < 100000 {
			return errors.New("PBKDF2 KDF iterations must be at least 100000.")
		}
	case KdfArgon2id:
		if k.Iterations < 1 {
			return errors.New("Argon2 KDF iterations must be at least 1.")
		}
		if k.MemoryMB < 15 || k.MemoryMB > 1024 {
			return errors.New("Argon2 memory must be between 15 MB and 1024 MB.")
		}
		if k.Parallelism < 1 || k.Parallelism > 16 {
			return errors.New("Argon2 parallelism must be between 1 and 16.")
		}
	default:
		return fmt.Errorf("unsupported KDF type: %d", k.Type)
	}
	return nil
}

// NormalizeSalt is the master-password salt: the trimmed, lowercased e-mail.
// Clients always use the e-mail itself, never a server-issued value.
func NormalizeSalt(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// DeriveMasterKey turns the user's master password into the 32-byte master
// key using the account's KDF settings.
func DeriveMasterKey(password, salt string, kdf KdfParams) ([]byte, error) {
	switch kdf.Type {
	case KdfPBKDF2SHA256:
		return pbkdf2.Key([]byte(password), []byte(salt), kdf.Iterations, 32, sha256.New), nil
	case KdfArgon2id:
		memory := uint32(kdf.MemoryMB) * 1024 // MB → KiB
		return argon2.IDKey([]byte(password), []byte(salt), uint32(kdf.Iterations), memory, uint8(kdf.Parallelism), 32), nil
	default:
		return nil, fmt.Errorf("unsupported KDF type: %d", kdf.Type)
	}
}

// HashMasterKey produces the value stored server-side to verify a login: the
// master key re-hashed with the e-mail as salt and a single PBKDF2 iteration.
// The password itself never reaches the server.
func HashMasterKey(masterKey []byte, salt string) string {
	hash := pbkdf2.Key(masterKey, []byte(salt), 1, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// VerifyMasterKey reports whether a client-sent master key matches the stored
// hash, in constant time.
func VerifyMasterKey(masterKey []byte, salt, storedHash string) bool {
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(storedHash))
	if err != nil || len(expected) == 0 {
		return false
	}
	actual := pbkdf2.Key(masterKey, []byte(salt), 1, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// StretchKey expands the 32-byte master key into the 64-byte symmetric key
// (AES-256 key ‖ HMAC-SHA256 key) used for every CipherString.
func StretchKey(masterKey []byte) []byte {
	// HKDF-Extract with a zero salt, then Expand with info "enc" for 64 bytes.
	prk := hkdf.Extract(sha256.New, masterKey, make([]byte, sha256.Size))
	reader := hkdf.Expand(sha256.New, prk, []byte("enc"))
	key := make([]byte, 64)
	if _, err := io.ReadFull(reader, key); err != nil {
		// Cannot happen: Expand yields exactly the requested length.
		panic("hkdf expand failed: " + err.Error())
	}
	return key
}

// GenerateUserKey returns a fresh 512-bit symmetric user key.
func GenerateUserKey() ([]byte, error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// WrapUserKey encrypts the user key with the stretched master key, producing
// the "Key" field stored on the account (a `2.` CipherString).
func WrapUserKey(masterKey, userKey []byte) (string, error) {
	return Encrypt(StretchKey(masterKey), userKey)
}

// UnwrapUserKey decrypts a stored account key with the stretched master key.
func UnwrapUserKey(masterKey []byte, wrapped string) ([]byte, error) {
	return Decrypt(StretchKey(masterKey), wrapped)
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func pad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("ciphertext empty")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// Encrypt produces a Bitwarden `2.` CipherString: AES-256-CBC with an
// HMAC-SHA256 authentication tag over iv‖ciphertext. key must be the
// 64-byte stretched key.
func Encrypt(key []byte, plaintext []byte) (string, error) {
	if len(key) != 64 {
		return "", errors.New("key must be 64 bytes (enc‖mac)")
	}
	encKey, macKey := key[:32], key[32:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	padded := pad(plaintext)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	mac := hmacSHA256(macKey, append(iv, ciphertext...))

	return fmt.Sprintf("2.%s.%s.%s", b64(iv), b64(ciphertext), b64(mac)), nil
}

// Decrypt verifies and decrypts a Bitwarden CipherString. Only the `2.`
// (and legacy `0.`, unencrypted) formats are supported.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	parts := strings.Split(encoded, ".")
	if len(parts) == 4 {
		if parts[0] != "2" {
			return nil, fmt.Errorf("unsupported cipher format %q", parts[0])
		}
		if len(key) != 64 {
			return nil, errors.New("key must be 64 bytes (enc‖mac)")
		}
		encKey, macKey := key[:32], key[32:]

		iv, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
		ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, err
		}
		mac, err := base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			return nil, err
		}
		expected := hmacSHA256(macKey, append(iv, ciphertext...))
		if subtle.ConstantTimeCompare(mac, expected) != 1 {
			return nil, errors.New("message authentication failed")
		}
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, err
		}
		if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
			return nil, errors.New("invalid ciphertext length")
		}
		plain := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
		return unpad(plain)
	}
	if len(parts) == 2 && parts[0] == "0" {
		// Legacy unencrypted value.
		return base64.RawURLEncoding.DecodeString(parts[1])
	}
	if len(parts) == 2 && parts[0] == "1" {
		// AES-CBC without MAC (legacy). Not produced by current clients.
		return nil, errors.New("legacy format 1 is not supported")
	}
	return nil, errors.New("invalid cipher string")
}

// DecryptString is Decrypt returning the plaintext as a string.
func DecryptString(key []byte, encoded string) (string, error) {
	plain, err := Decrypt(key, encoded)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// GenerateKeyPair creates the per-account RSA key pair. The public key is
// exported as base64 SPKI DER and the private key as base64 PKCS#1 DER,
// which is what upstream clients expect on the wire.
func GenerateKeyPair() (publicKey string, privateKey string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	privDER := x509.MarshalPKCS1PrivateKey(key)
	return base64.StdEncoding.EncodeToString(pubDER), base64.StdEncoding.EncodeToString(privDER), nil
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// EncryptPrivateKey wraps the private key with the user's symmetric key so
// only the account owner can use it.
func EncryptPrivateKey(userKey []byte, privateKeyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", err
	}
	return Encrypt(userKey, raw)
}
