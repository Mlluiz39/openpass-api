package vault

import (
	"context"
	"testing"
)

func TestHostScoreRanksRelationships(t *testing.T) {
	cases := []struct {
		visited, stored string
		want            int
	}{
		{"github.com", "github.com", 100},
		{"www.github.com", "github.com", 80}, // hostname() strips www before scoring
		{"mail.example.com", "example.com", 80},
		{"example.com", "mail.example.com", 60},
		{"app.example.com", "www.example.com", 40},
		{"evil.example", "bank.example", 0},
		{"github.com", "gitlab.com", 0},
		{"example.com.evil.test", "example.com", 0},
	}
	for _, c := range cases {
		if got := hostScore(c.visited, c.stored); got != c.want {
			t.Errorf("hostScore(%q, %q) = %d, want %d", c.visited, c.stored, got, c.want)
		}
	}
}

func TestHostnameNormalizesURLs(t *testing.T) {
	cases := map[string]string{
		"https://www.github.com/login": "github.com",
		"HTTP://Example.COM:8443/x":    "example.com",
		"github.com":                   "github.com",
		"  https://mail.example.com ":  "mail.example.com",
		"":                             "",
	}
	for in, want := range cases {
		if got := hostname(in); got != want {
			t.Errorf("hostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchEntriesFindsSiteAndWithholdsSecretsByDefault(t *testing.T) {
	database := testDB(t)
	svc := New(database, "secret")
	owner := testOwner(t, database, "owner-match")

	v, err := svc.CreateVault(context.Background(), owner, VaultInput{Name: "Principal"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	for _, in := range []EntryInput{
		{VaultID: v.ID, Path: "GitHub", Type: "login", Value: "gh-secret", Metadata: map[string]string{"url": "https://github.com/login", "username": "octocat"}},
		{VaultID: v.ID, Path: "GitLab", Type: "login", Value: "gl-secret", Metadata: map[string]string{"url": "https://gitlab.com", "username": "octocat"}},
		{VaultID: v.ID, Path: "Banco", Type: "login", Value: "bank-secret", Metadata: map[string]string{"url": "https://bank.example", "username": "me"}},
		{VaultID: v.ID, Path: "Nota", Type: "note", Value: "texto", Metadata: map[string]string{"url": "https://github.com"}},
	} {
		if _, err := svc.CreateEntry(context.Background(), owner, in); err != nil {
			t.Fatalf("CreateEntry(%s) error = %v", in.Path, err)
		}
	}

	matches, err := svc.MatchEntries(context.Background(), owner, "https://github.com/settings", false)
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want only GitHub: %+v", len(matches), matches)
	}
	if matches[0].Entry.Path != "GitHub" {
		t.Fatalf("matched %q, want GitHub", matches[0].Entry.Path)
	}
	if matches[0].Value != "" {
		t.Fatalf("a plain match leaked a secret: %q", matches[0].Value)
	}

	revealed, err := svc.MatchEntries(context.Background(), owner, "https://github.com/settings", true)
	if err != nil {
		t.Fatalf("MatchEntries(reveal) error = %v", err)
	}
	if len(revealed) != 1 || revealed[0].Value != "gh-secret" {
		t.Fatalf("reveal gave %+v, want gh-secret", revealed)
	}
}

func TestMatchEntriesOrdersSubdomainsAboveSameDomain(t *testing.T) {
	database := testDB(t)
	svc := New(database, "secret")
	owner := testOwner(t, database, "owner-match-2")

	v, err := svc.CreateVault(context.Background(), owner, VaultInput{Name: "Principal"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	for _, in := range []EntryInput{
		{VaultID: v.ID, Path: "Example raiz", Type: "login", Value: "a", Metadata: map[string]string{"url": "https://example.com"}},
		{VaultID: v.ID, Path: "Mail", Type: "login", Value: "b", Metadata: map[string]string{"url": "https://mail.example.com"}},
	} {
		if _, err := svc.CreateEntry(context.Background(), owner, in); err != nil {
			t.Fatalf("CreateEntry() error = %v", err)
		}
	}

	matches, err := svc.MatchEntries(context.Background(), owner, "https://mail.example.com/inbox", false)
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}
	if matches[0].Entry.Path != "Mail" {
		t.Fatalf("best match = %q, want Mail (exact host)", matches[0].Entry.Path)
	}
}

func TestMatchEntriesIgnoresUnrelatedSites(t *testing.T) {
	database := testDB(t)
	svc := New(database, "secret")
	owner := testOwner(t, database, "owner-match-3")

	v, err := svc.CreateVault(context.Background(), owner, VaultInput{Name: "Principal"})
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if _, err := svc.CreateEntry(context.Background(), owner, EntryInput{
		VaultID: v.ID, Path: "Banco", Type: "login", Value: "s",
		Metadata: map[string]string{"url": "https://banco.example"},
	}); err != nil {
		t.Fatalf("CreateEntry() error = %v", err)
	}

	// A look-alike domain must not receive the credentials.
	matches, err := svc.MatchEntries(context.Background(), owner, "https://banco.example.evil.test/login", false)
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("look-alike host matched %+v, want nothing", matches)
	}
}

func TestMatchEntriesNeedsAURL(t *testing.T) {
	database := testDB(t)
	svc := New(database, "secret")
	owner := testOwner(t, database, "owner-match-4")

	matches, err := svc.MatchEntries(context.Background(), owner, "", false)
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("empty URL produced %d matches", len(matches))
	}
}
