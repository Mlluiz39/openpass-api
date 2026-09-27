package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashes use the PHC string representation of argon2id:
//
//	argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
//
// Passwords migrated from the single-admin era are stored as
// "legacy-sha256:<salt>:<hash>" and are transparently re-hashed to argon2id
// on the first successful login (VerifyPassword reports needsRehash).
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	passwordPrefix = "argon2id$"
	legacyPrefix   = "legacy-sha256:"
)

// HashPassword hashes a password with argon2id and a fresh random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s",
		passwordPrefix,
		19, // argon2 version 0x13, as in the PHC string format
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks password against a stored hash in any supported
// format. needsRehash is true when the password matched but the stored format
// is outdated (the legacy single-admin SHA-256), so the caller can upgrade it.
func VerifyPassword(password, stored string) (ok bool, needsRehash bool) {
	switch {
	case strings.HasPrefix(stored, passwordPrefix):
		return verifyArgon2id(password, stored), false
	case strings.HasPrefix(stored, legacyPrefix):
		return verifyLegacySHA256(password, stored), true
	default:
		return false, false
	}
}

func verifyArgon2id(password, stored string) bool {
	parts := strings.Split(strings.TrimPrefix(stored, passwordPrefix), "$")
	if len(parts) != 4 {
		return false
	}
	// parts[0] = "v=19", parts[1] = "m=...,t=...,p=...", parts[2] = salt, parts[3] = hash.
	if !strings.HasPrefix(parts[0], "v=") {
		return false
	}
	var memory, time uint32
	var threads uint8
	for _, param := range strings.Split(parts[1], ",") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return false
		}
		value, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false
		}
		switch kv[0] {
		case "m":
			memory = uint32(value)
		case "t":
			time = uint32(value)
		case "p":
			threads = uint8(value)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func verifyLegacySHA256(password, stored string) bool {
	payload := strings.TrimPrefix(stored, legacyPrefix)
	salt, hash, found := strings.Cut(payload, ":")
	if !found || salt == "" || hash == "" {
		return false
	}
	return VerifySHA256(salt+":"+password, hash)
}

// BuildLegacyHash encodes the pre-argon2id storage format from its two
// pieces (salt and hash) as they existed in the old app_settings table. Used
// by the SQLite migration tool and its tests.
func BuildLegacyHash(salt, hash string) string {
	if salt == "" || hash == "" {
		return ""
	}
	return legacyPrefix + salt + ":" + hash
}
