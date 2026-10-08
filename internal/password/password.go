// Package password generates random passwords and passphrases, the way a
// password manager's generator does.
//
// Everything here reads from crypto/rand: a generator that used math/rand
// would produce passwords that look random and are trivially predictable.
package password

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// Character classes. Ambiguous glyphs (l/1/I, O/0) are excluded only when the
// caller asks, because some sites still reject them while most do not.
const (
	lower          = "abcdefghijklmnopqrstuvwxyz"
	upper          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits         = "0123456789"
	symbols        = "!@#$%^&*()-_=+[]{};:,.?/"
	ambiguous      = "il1IoO0"
	maxLength      = 256
	minLength      = 4
	defaultSymbols = "--"
)

// Options describes the password to produce.
type Options struct {
	// Length is the total number of characters.
	Length int `json:"length"`
	// Lower, Upper, Digits and Symbols select the character classes to draw
	// from. At least one has to be on.
	Lower   bool `json:"lower"`
	Upper   bool `json:"upper"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
	// ExcludeAmbiguous drops glyphs that are easy to confuse when read aloud.
	ExcludeAmbiguous bool `json:"exclude_ambiguous"`
}

// DefaultOptions is a reasonable generator preset: 20 characters, all classes.
func DefaultOptions() Options {
	return Options{Length: 20, Lower: true, Upper: true, Digits: true, Symbols: true}
}

// Generate returns a password satisfying the options.
//
// The password contains at least one character from every selected class: a
// uniformly random draw over all classes can return a value with no digits at
// all, which many sites reject, so one character per class is placed first and
// the rest are drawn from the pool. The result is then shuffled so the fixed
// positions do not leak the class layout.
func Generate(opts Options) (string, error) {
	if opts.Length < minLength {
		return "", errors.New("o comprimento mínimo é 4")
	}
	if opts.Length > maxLength {
		return "", errors.New("o comprimento máximo é 256")
	}

	pools := make([]string, 0, 4)
	if opts.Lower {
		pools = append(pools, class(lower, opts.ExcludeAmbiguous))
	}
	if opts.Upper {
		pools = append(pools, class(upper, opts.ExcludeAmbiguous))
	}
	if opts.Digits {
		pools = append(pools, class(digits, opts.ExcludeAmbiguous))
	}
	if opts.Symbols {
		pools = append(pools, symbols)
	}

	pool := strings.Join(pools, "")
	if pool == "" {
		return "", errors.New("selecione ao menos um tipo de caractere")
	}
	if opts.Length < len(pools) {
		return "", errors.New("comprimento curto demais para os tipos escolhidos")
	}

	out := make([]rune, 0, opts.Length)
	for _, p := range pools {
		if p == "" {
			return "", errors.New("um dos tipos escolhidos ficou sem caracteres (tente desativar os ambíguos)")
		}
		c, err := pick(p)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}

	poolRunes := []rune(pool)
	for len(out) < opts.Length {
		c, err := pickRune(poolRunes)
		if err != nil {
			return "", err
		}
		out = append(out, c)
	}

	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// Passphrase builds a passphrase of `Words` dictionary words, joined by sep.
//
// Word-based secrets are longer but far easier to type and remember; the
// strength comes from the word count, not from the separator.
func Passphrase(words []string, count int, sep string) (string, error) {
	if len(words) == 0 {
		return "", errors.New("dicionário vazio")
	}
	if count < 3 {
		return "", errors.New("use pelo menos 3 palavras")
	}
	if count > 12 {
		return "", errors.New("use no máximo 12 palavras")
	}
	if sep == "" {
		sep = "-"
	}

	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		w, err := pickList(words)
		if err != nil {
			return "", err
		}
		// Capitalize the first word only, so the result reads like a phrase.
		if i == 0 {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, sep), nil
}

// Strength estimates the entropy of a password in bits, so the UI can show
// something more honest than "strong/weak".
func Strength(password string) float64 {
	if password == "" {
		return 0
	}
	pool := 0
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case strings.ContainsRune(lower, r):
			hasLower = true
		case strings.ContainsRune(upper, r):
			hasUpper = true
		case strings.ContainsRune(digits, r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += len(symbols)
	}
	if pool == 0 {
		return 0
	}

	// log2(pool) * length, computed without importing math for one call.
	bits := 0.0
	for p := pool; p > 1; p >>= 1 {
		bits++
	}
	// Refine the integer log2 with the fractional part for a smoother estimate.
	remainder := float64(pool) / float64(int(1)<<int(bits))
	if remainder > 0 {
		bits += (remainder - 1)
	}
	return bits * float64(len([]rune(password)))
}

// class returns a character set, optionally without the ambiguous glyphs.
func class(set string, excludeAmbiguous bool) string {
	if !excludeAmbiguous {
		return set
	}
	var b strings.Builder
	for _, r := range set {
		if !strings.ContainsRune(ambiguous, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// pick returns one character from set.
func pick(set string) (rune, error) {
	return pickRune([]rune(set))
}

// pickRune returns one element, using rejection-free crypto/rand indexing:
// big.Int is used because it removes the modulo bias a naive `% len` has.
func pickRune(set []rune) (rune, error) {
	if len(set) == 0 {
		return 0, errors.New("conjunto vazio")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func pickList(items []string) (string, error) {
	if len(items) == 0 {
		return "", errors.New("lista vazia")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(items))))
	if err != nil {
		return "", err
	}
	return items[n.Int64()], nil
}

// shuffle applies a Fisher-Yates pass driven by crypto/rand.
func shuffle(values []rune) error {
	for i := len(values) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := n.Int64()
		values[i], values[j] = values[j], values[i]
	}
	return nil
}
