// Package totp implements the time-based one-time passwords (RFC 6238) used by
// every "authenticator app" 2FA flow, so OpenPass can act as the authenticator
// instead of the user reaching for their phone.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Defaults from RFC 6238 / the otpauth:// convention.
const (
	DefaultDigits = 6
	DefaultPeriod = 30
)

// Config is a parsed authenticator secret.
type Config struct {
	// Secret is the raw base32 secret (unpadded, upper case).
	Secret string
	// Digits is how many digits the code has; 6 unless the issuer says otherwise.
	Digits int
	// Period is the code's lifetime in seconds; 30 unless overridden.
	Period int
	// Algorithm is SHA1, SHA256 or SHA512.
	Algorithm string
	// Issuer and Account are display labels from an otpauth:// URI.
	Issuer  string
	Account string
}

// Code is a generated one-time password, ready to display.
type Code struct {
	// Code is the zero-padded numeric code, e.g. "048213".
	Code string `json:"code"`
	// Period is the full lifetime of this code in seconds.
	Period int `json:"period"`
	// SecondsRemaining is how long this code stays valid.
	SecondsRemaining int `json:"seconds_remaining"`
	// Digits mirrors the configuration, for the UI to render consistently.
	Digits int `json:"digits"`
}

// Parse accepts either an otpauth:// URI (what QR codes contain) or a bare
// base32 secret (what sites show next to the QR code), and returns the
// parameters to generate codes with.
//
// Spaces, dashes and lower case are tolerated in a bare secret because sites
// format them inconsistently and rejecting them would only confuse the user.
func Parse(input string) (Config, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Config{}, errors.New("segredo vazio")
	}

	cfg := Config{Digits: DefaultDigits, Period: DefaultPeriod, Algorithm: "SHA1"}

	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return Config{}, fmt.Errorf("URI otpauth inválida: %w", err)
		}
		if strings.ToLower(parsed.Host) != "totp" {
			return Config{}, fmt.Errorf("tipo %q não suportado (apenas totp)", parsed.Host)
		}
		q := parsed.Query()
		cfg.Secret = q.Get("secret")
		if v := q.Get("digits"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 6 || n > 10 {
				return Config{}, fmt.Errorf("digits inválido: %q", v)
			}
			cfg.Digits = n
		}
		if v := q.Get("period"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return Config{}, fmt.Errorf("period inválido: %q", v)
			}
			cfg.Period = n
		}
		if v := strings.ToUpper(q.Get("algorithm")); v != "" {
			cfg.Algorithm = v
		}
		// The label is "Issuer:Account" (per the Key URI format), with a
		// separate issuer parameter taking precedence when both are present.
		label := strings.TrimPrefix(parsed.Path, "/")
		if unescaped, err := url.PathUnescape(label); err == nil {
			label = unescaped
		}
		if issuer, account, found := strings.Cut(label, ":"); found {
			cfg.Issuer = strings.TrimSpace(issuer)
			cfg.Account = strings.TrimSpace(account)
		} else {
			cfg.Account = strings.TrimSpace(label)
		}
		if issuerParam := strings.TrimSpace(q.Get("issuer")); issuerParam != "" {
			cfg.Issuer = issuerParam
		}
	} else {
		cfg.Secret = raw
	}

	normalized, err := normalizeSecret(cfg.Secret)
	if err != nil {
		return Config{}, err
	}
	cfg.Secret = normalized

	switch cfg.Algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		return Config{}, fmt.Errorf("algoritmo não suportado: %q", cfg.Algorithm)
	}
	return cfg, nil
}

// normalizeSecret strips the formatting sites add and validates the base32.
func normalizeSecret(secret string) (string, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(secret))
	cleaned = strings.NewReplacer(" ", "", "-", "", "=", "").Replace(cleaned)
	if cleaned == "" {
		return "", errors.New("segredo vazio")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned); err != nil {
		return "", errors.New("segredo não está em base32 válido")
	}
	return cleaned, nil
}

// Generate returns the code for the given instant.
func Generate(cfg Config, at time.Time) (Code, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cfg.Secret)
	if err != nil {
		return Code{}, errors.New("segredo não está em base32 válido")
	}

	period := cfg.Period
	if period <= 0 {
		period = DefaultPeriod
	}
	digits := cfg.Digits
	if digits <= 0 {
		digits = DefaultDigits
	}

	counter := uint64(at.UTC().Unix() / int64(period))

	var mac hash.Hash
	switch cfg.Algorithm {
	case "SHA256":
		mac = hmac.New(sha256.New, key)
	case "SHA512":
		mac = hmac.New(sha512.New, key)
	default:
		mac = hmac.New(sha1.New, key)
	}

	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter)
		counter >>= 8
	}
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte
	// picks the 4-byte window, and the top bit is masked off.
	offset := sum[len(sum)-1] & 0x0f
	binary := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(math.Pow10(digits))
	value := binary % mod

	remaining := period - int(at.UTC().Unix()%int64(period))
	if remaining <= 0 {
		remaining = period
	}

	return Code{
		Code:             fmt.Sprintf("%0*d", digits, value),
		Period:           period,
		SecondsRemaining: remaining,
		Digits:           digits,
	}, nil
}

// Validate reports whether the input can be used as a TOTP secret, so the API
// can reject a typo at save time instead of failing when the user needs a code.
func Validate(input string) error {
	_, err := Parse(input)
	return err
}
