package password

import (
	"strings"
	"testing"
)

func TestGenerateRespectsLengthAndClasses(t *testing.T) {
	opts := DefaultOptions()
	opts.Length = 24

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		got, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if len([]rune(got)) != 24 {
			t.Fatalf("length = %d, want 24 (%q)", len([]rune(got)), got)
		}
		if seen[got] {
			t.Fatalf("Generate() repeated a password after %d draws: %q", i, got)
		}
		seen[got] = true

		if !strings.ContainsAny(got, digits) {
			t.Errorf("no digit in %q", got)
		}
		if !strings.ContainsAny(got, upper) {
			t.Errorf("no upper-case letter in %q", got)
		}
		if !strings.ContainsAny(got, lower) {
			t.Errorf("no lower-case letter in %q", got)
		}
		if !strings.ContainsAny(got, symbols) {
			t.Errorf("no symbol in %q", got)
		}
	}
}

func TestGenerateOnlyUsesSelectedClasses(t *testing.T) {
	got, err := Generate(Options{Length: 32, Digits: true})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, r := range got {
		if !strings.ContainsRune(digits, r) {
			t.Fatalf("digit-only request produced %q", got)
		}
	}
}

func TestGenerateExcludesAmbiguousCharacters(t *testing.T) {
	opts := Options{Length: 64, Lower: true, Upper: true, Digits: true, ExcludeAmbiguous: true}
	for i := 0; i < 50; i++ {
		got, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if strings.ContainsAny(got, ambiguous) {
			t.Fatalf("ambiguous character in %q", got)
		}
	}
}

func TestGenerateRejectsBadOptions(t *testing.T) {
	// The "more classes than characters" guard is unreachable through this
	// API: four classes with a minimum length of four still fits. Only the
	// reachable rejections are asserted here.
	for name, opts := range map[string]Options{
		"no class":  {Length: 20},
		"too short": {Length: 3, Lower: true},
		"too long":  {Length: 300, Lower: true},
	} {
		if _, err := Generate(opts); err == nil {
			t.Errorf("%s: Generate() succeeded, want an error", name)
		}
	}
}

func TestPassphraseUsesEveryWordOnce(t *testing.T) {
	dict := []string{"casa", "azul", "verde"}

	got, err := Passphrase(dict, 3, "-")
	if err != nil {
		t.Fatalf("Passphrase() error = %v", err)
	}
	parts := strings.Split(got, "-")
	if len(parts) != 3 {
		t.Fatalf("got %d words in %q, want 3", len(parts), got)
	}
	if strings.ToUpper(parts[0][:1]) != parts[0][:1] {
		t.Errorf("first word not capitalized: %q", got)
	}
	for _, p := range parts {
		if !containsFold(dict, p) {
			t.Errorf("word %q is not in the dictionary (from %q)", p, got)
		}
	}
}

func TestPassphraseRejectsBadWordCounts(t *testing.T) {
	dict := []string{"casa", "azul"}
	if _, err := Passphrase(dict, 2, "-"); err == nil {
		t.Error("Passphrase(2 words) succeeded, want an error")
	}
	if _, err := Passphrase(dict, 13, "-"); err == nil {
		t.Error("Passphrase(13 words) succeeded, want an error")
	}
	if _, err := Passphrase(nil, 4, "-"); err == nil {
		t.Error("Passphrase(empty dictionary) succeeded, want an error")
	}
}

func TestStrengthGrowsWithLengthAndVariety(t *testing.T) {
	short := Strength("abc")
	long := Strength("abcabcabcabcabcabcabc")
	if !(long > short) {
		t.Errorf("Strength(long)=%f not above Strength(short)=%f", long, short)
	}

	mixed := Strength("aA1!aA1!aA1!aA1!")
	plain := Strength("aaaaaaaaaaaaaaaa")
	if !(mixed > plain) {
		t.Errorf("Strength(mixed)=%f not above Strength(plain)=%f", mixed, plain)
	}
	if Strength("") != 0 {
		t.Errorf("Strength(\"\") = %f, want 0", Strength(""))
	}
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
