package bitwarden

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// secureCompare compares two strings in constant time.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// cryptoSHA256 is the hash identifier rsa.SignPKCS1v15/VerifyPKCS1v15 expect.
const cryptoSHA256 = crypto.SHA256

// timeFormat is the date format upstream uses on the wire
// (e.g. "2026-10-11T12:34:56.789Z").
const timeFormat = "2006-01-02T15:04:05.000Z"

func nowBitwarden() string {
	return time.Now().UTC().Format(timeFormat)
}

func formatBitwardenTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// parseBitwardenTime accepts both the wire format and plain RFC3339.
func parseBitwardenTime(value string) (time.Time, error) {
	if t, err := time.Parse(timeFormat, value); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, value)
}

func randomToken(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// randomUUID returns a random v4-shaped UUID, the identifier style upstream
// clients use for devices and ciphers.
func randomUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	s := hex.EncodeToString(buf)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

func marshalJOSE(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeJOSE(header, claims string) (map[string]any, map[string]any, error) {
	headerRaw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, nil, err
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(claims)
	if err != nil {
		return nil, nil, err
	}
	var h, c map[string]any
	if err := json.Unmarshal(headerRaw, &h); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(claimsRaw, &c); err != nil {
		return nil, nil, err
	}
	return h, c, nil
}

// bigEndianBytes encodes a small int (RSA exponent) as big-endian bytes
// without leading zeros, as JWK requires.
func bigEndianBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var out []byte
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}
	return out
}

// domainFromRequest rebuilds the public base URL of this server from the
// request, honouring a TLS terminator in front (X-Forwarded-Proto). An
// explicit OPENPASS_BW_DOMAIN takes precedence when set.
func domainFromRequest(r *http.Request, configured string) string {
	if configured = strings.TrimRight(strings.TrimSpace(configured), "/"); configured != "" {
		return configured
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// decodeB64Key accepts the standard and raw (unpadded) base64 variants a
// client may use for the master key it derives locally.
func decodeB64Key(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(value)
}
