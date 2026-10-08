package totp

import (
	"testing"
	"time"
)

// The RFC 6238 Appendix B vectors. Their secrets are the ASCII strings
// "1234567890...", base32-encoded here; the expected codes are the published
// ones, so passing means the implementation agrees with every other TOTP
// authenticator rather than merely with itself.
const (
	secretSHA1   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secretSHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	secretSHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
)

func TestGenerateMatchesRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix   int64
		sha1   string
		sha256 string
		sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, c := range cases {
		at := time.Unix(c.unix, 0).UTC()
		for _, tc := range []struct {
			secret, algorithm, want string
		}{
			{secretSHA1, "SHA1", c.sha1},
			{secretSHA256, "SHA256", c.sha256},
			{secretSHA512, "SHA512", c.sha512},
		} {
			cfg, err := Parse(tc.secret)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			cfg.Algorithm = tc.algorithm
			cfg.Digits = 8

			got, err := Generate(cfg, at)
			if err != nil {
				t.Fatalf("Generate(%s, %d) error = %v", tc.algorithm, c.unix, err)
			}
			if got.Code != tc.want {
				t.Errorf("%s at %d = %s, want %s", tc.algorithm, c.unix, got.Code, tc.want)
			}
		}
	}
}

func TestParseAcceptsOtpAuthURI(t *testing.T) {
	uri := "otpauth://totp/GitHub:octocat@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8&period=60&algorithm=SHA256"
	cfg, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Secret != secretSHA1 {
		t.Errorf("Secret = %q, want %q", cfg.Secret, secretSHA1)
	}
	if cfg.Digits != 8 {
		t.Errorf("Digits = %d, want 8", cfg.Digits)
	}
	if cfg.Period != 60 {
		t.Errorf("Period = %d, want 60", cfg.Period)
	}
	if cfg.Algorithm != "SHA256" {
		t.Errorf("Algorithm = %q, want SHA256", cfg.Algorithm)
	}
	if cfg.Issuer != "GitHub" {
		t.Errorf("Issuer = %q, want GitHub", cfg.Issuer)
	}
	if cfg.Account != "octocat@example.com" {
		t.Errorf("Account = %q, want octocat@example.com", cfg.Account)
	}
}

func TestParseDefaultsToSixDigitsAndThirtySeconds(t *testing.T) {
	cfg, err := Parse(secretSHA1)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Digits != 6 || cfg.Period != 30 || cfg.Algorithm != "SHA1" {
		t.Fatalf("defaults = %d/%d/%s, want 6/30/SHA1", cfg.Digits, cfg.Period, cfg.Algorithm)
	}
}

func TestParseToleratesFormattingOfBareSecrets(t *testing.T) {
	// Sites print the same secret lower case, in groups, or with padding.
	for _, in := range []string{
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
	} {
		cfg, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", in, err)
		}
		if cfg.Secret != secretSHA1 {
			t.Errorf("Parse(%q).Secret = %q, want %q", in, cfg.Secret, secretSHA1)
		}
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	for _, in := range []string{
		"",
		"não-é-base32!!",
		"otpauth://hotp/foo?secret=" + secretSHA1, // counter-based, not supported
		"otpauth://totp/foo?secret=" + secretSHA1 + "&algorithm=MD5",
		"otpauth://totp/foo?secret=" + secretSHA1 + "&digits=4",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", in)
		}
	}
}

func TestGenerateReportsTimeRemaining(t *testing.T) {
	cfg, err := Parse(secretSHA1)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// 1000000010 is 20s into a 30s window, leaving 10.
	got, err := Generate(cfg, time.Unix(1000000010, 0).UTC())
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if got.SecondsRemaining != 10 {
		t.Errorf("SecondsRemaining = %d, want 10", got.SecondsRemaining)
	}
	if got.Period != 30 {
		t.Errorf("Period = %d, want 30", got.Period)
	}

	// At the exact start of a window the full period remains.
	got, err = Generate(cfg, time.Unix(1000000020, 0).UTC()) // 1000000020 % 30 == 0
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if got.SecondsRemaining != 30 {
		t.Errorf("SecondsRemaining = %d, want 30", got.SecondsRemaining)
	}
}

func TestGenerateStaysStableWithinTheSameWindow(t *testing.T) {
	cfg, _ := Parse(secretSHA1)
	first, err := Generate(cfg, time.Unix(1111111109, 0).UTC())
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	for _, offset := range []int64{1, 10, 29} {
		other, err := Generate(cfg, time.Unix(1111111080+offset, 0).UTC())
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}
		if other.Code != first.Code {
			t.Errorf("code changed %ds into the window: %s → %s", offset, first.Code, other.Code)
		}
	}
	next, err := Generate(cfg, time.Unix(1111111080+30, 0).UTC())
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if next.Code == first.Code {
		t.Errorf("code did not change in the next window (still %s)", next.Code)
	}
}
