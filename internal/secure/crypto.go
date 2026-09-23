package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type APIKey struct {
	Plaintext string
	Prefix    string
	Suffix    string
	Hash      string
}

func GenerateAPIKey(env string) (APIKey, error) {
	if env != "live" && env != "test" && env != "" && env != "none" && env != "raw" {
		return APIKey{}, fmt.Errorf("unsupported key env: %s", env)
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return APIKey{}, err
	}
	token := hex.EncodeToString(raw)
	plaintext := token
	if env == "live" || env == "test" {
		plaintext = fmt.Sprintf("op_%s_%s", env, token)
	}
	return NewAPIKey(plaintext)
}

func NewAPIKey(plaintext string) (APIKey, error) {
	plaintext = strings.TrimSpace(plaintext)
	if len(plaintext) < 8 {
		return APIKey{}, errors.New("key must be at least 8 characters")
	}
	suffix := plaintext
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	return APIKey{
		Plaintext: plaintext,
		Prefix:    ExtractPrefix(plaintext),
		Suffix:    suffix,
		Hash:      SHA256Hex(plaintext),
	}, nil
}

func ExtractPrefix(token string) string {
	token = strings.TrimSpace(token)
	if len(token) < 8 {
		return ""
	}
	if len(token) < 16 {
		return token
	}
	return token[:16]
}

func SHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func VerifySHA256(value, expectedHash string) bool {
	actual := SHA256Hex(value)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedHash)) == 1
}

type Box struct {
	key [32]byte
}

func NewBox(secret string) Box {
	return Box{key: sha256.Sum256([]byte(secret))}
}

func (b Box) EncryptString(plaintext string) (string, error) {
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v1:" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (b Box) DecryptString(ciphertext string) (string, error) {
	encoded := strings.TrimPrefix(ciphertext, "v1:")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(b.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := raw[:gcm.NonceSize()]
	data := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
