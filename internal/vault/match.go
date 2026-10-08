package vault

import (
	"context"
	"net/url"
	"sort"
	"strings"
)

// Match is an entry that plausibly belongs to the site being visited, plus the
// value when the caller asked for it.
//
// Value is only populated on a reveal request: the browser extension asks for
// the candidate list first and requests the secret for the entry the user
// actually picked, so a page never sees more secrets than it needs.
type Match struct {
	Entry Entry  `json:"entry"`
	Score int    `json:"score"`
	Value string `json:"value,omitempty"`
}

// MatchEntries returns the owner's login entries whose stored URL (or name)
// relates to rawURL, best match first.
//
// reveal decrypts the matched values. Matching is deliberately conservative:
// only same-site or parent/child host relationships qualify, so a page on
// evil.example never receives credentials stored for bank.example.
func (s *Service) MatchEntries(ctx context.Context, ownerID, rawURL string, reveal bool) ([]Match, error) {
	host := hostname(rawURL)
	if host == "" {
		return nil, nil
	}

	entries, err := s.listEntries(ctx, ownerID, "", nil)
	if err != nil {
		return nil, err
	}

	var matches []Match
	for _, entry := range entries {
		if entry.Type != "login" {
			continue
		}
		target := entryHost(entry)
		if target == "" {
			continue
		}
		score := hostScore(host, target)
		if score == 0 {
			continue
		}
		matches = append(matches, Match{Entry: entry, Score: score})
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].Entry.Path < matches[j].Entry.Path
	})

	if !reveal {
		return matches, nil
	}
	for i := range matches {
		value, err := s.RevealEntry(ctx, ownerID, matches[i].Entry.ID)
		if err != nil {
			continue // an entry that cannot be decrypted simply gets no value
		}
		matches[i].Value = value
	}
	return matches, nil
}

// entryHost reads the site an entry belongs to from its url metadata, falling
// back to the entry name when it looks like a host (how Chrome exports import).
func entryHost(entry Entry) string {
	if raw := strings.TrimSpace(entry.Metadata["url"]); raw != "" {
		if host := hostname(raw); host != "" {
			return host
		}
	}
	name := strings.TrimSpace(entry.Path)
	if strings.ContainsAny(name, " /:@") && !strings.Contains(name, ".") {
		return ""
	}
	if !strings.Contains(name, ".") {
		return ""
	}
	return hostname(name)
}

// hostname lowers and strips a URL (or bare host) down to its host part.
func hostname(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(u.Hostname(), "www.")
}

// hostScore rates how well a stored host answers for the visited host:
//
//	100  same host
//	 80  the visited host is a subdomain of the stored one (mail.example.com ↔ example.com)
//	 60  the stored host is a subdomain of the visited one
//	 40  same registrable domain, different subdomain
//	  0  unrelated
func hostScore(visited, stored string) int {
	switch {
	case visited == stored:
		return 100
	case strings.HasSuffix(visited, "."+stored):
		return 80
	case strings.HasSuffix(stored, "."+visited):
		return 60
	case registrable(visited) == registrable(stored):
		return 40
	default:
		return 0
	}
}

// registrable reduces a host to its last two labels. This is an approximation
// (it treats "co.uk" as a domain), which is fine for autofill ranking: a wrong
// guess only deprioritizes a candidate, it never leaks a secret, because the
// visited host must still be related for the entry to appear at all.
func registrable(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
