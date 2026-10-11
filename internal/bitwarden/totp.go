package bitwarden

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// otpAlphabet matches authenticator apps: Crockford-ish base32 without
// padding, the format clients expect on the otpauth:// URI.
var otpAlphabet = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)

// GenerateTOTPSeed returns a fresh 160-bit TOTP seed (RFC 4226
// recommendation) encoded as base32.
func GenerateTOTPSeed() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return otpAlphabet.EncodeToString(secret), nil
}

// ValidateTOTP checks a 6-digit code against the base32 secret, accepting
// the previous/current/next time step to tolerate clock skew.
func ValidateTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	key, err := otpAlphabet.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	counter := now.UTC().Unix() / 30
	for _, c := range []int64{counter - 1, counter, counter + 1} {
		if c < 0 {
			continue
		}
		if subtleTotpEqual(hotp(key, uint64(c)), code) {
			return true
		}
	}
	return false
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

func subtleTotpEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
