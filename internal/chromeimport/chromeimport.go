// Package chromeimport imports Google Chrome / Chromium password exports
// (the CSV produced by chrome://password-manager → "Baixar arquivo") into an
// OpenPass vault.
//
// Importing goes through vault.Service, so values are encrypted with the same
// app secret, ownership rules apply, and duplicates are rejected by the
// (vault_id, path) uniqueness constraint.
package chromeimport

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/openpass/api/internal/vault"
)

// Result summarizes an import run.
type Result struct {
	// VaultID is the vault the entries landed in.
	VaultID string `json:"vault_id"`
	// VaultName is the destination vault's name ("Principal" by default).
	VaultName string `json:"vault_name"`
	// Imported counts freshly created entries.
	Imported int `json:"imported"`
	// Skipped counts rows with no password or with a name already in the vault.
	Skipped int `json:"skipped"`
	// Failed counts rows the vault rejected (e.g. duplicate race).
	Failed int `json:"failed"`
	// Names lists the entries created in this run (never their values).
	Names []string `json:"names"`
	// Errors lists per-row failures, for the operator to inspect.
	Errors []string `json:"errors,omitempty"`
	// DryRun marks a run that only reported what would happen.
	DryRun bool `json:"dry_run,omitempty"`
}

// Options controls an import run.
type Options struct {
	// VaultName is the destination vault; empty means "Principal".
	VaultName string
	// DryRun reports what would be imported without writing anything.
	DryRun bool
}

// CSVFromString parses the Chrome CSV held in a string.
func CSVFromString(content string) ([][]string, error) {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	return r.ReadAll()
}

// Import parses the Chrome CSV (as exported by Chrome's password manager) and
// writes each row as a `login` entry in the owner's destination vault.
//
// Rows without a password are skipped; rows whose name already exists are
// skipped rather than overwritten, so re-running an export is safe.
func Import(ctx context.Context, svc *vault.Service, ownerID, csvContent string, opts Options) (Result, error) {
	vaultName := strings.TrimSpace(opts.VaultName)
	if vaultName == "" {
		vaultName = "Principal"
	}

	res := Result{VaultName: vaultName, Names: []string{}, DryRun: opts.DryRun}

	rows, err := CSVFromString(csvContent)
	if err != nil {
		return res, fmt.Errorf("CSV inválido: %w", err)
	}
	if len(rows) < 1 {
		return res, errors.New("CSV vazio")
	}

	cols := map[string]int{}
	for i, h := range rows[0] {
		cols[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	if _, ok := cols["password"]; !ok {
		return res, fmt.Errorf("CSV sem coluna 'password' (cabeçalho lido: %v)", rows[0])
	}

	// Destination vault: reuse the existing one or create it.
	destination := ""
	vaults, err := svc.ListVaults(ctx, ownerID, nil)
	if err != nil {
		return res, err
	}
	for _, v := range vaults {
		if strings.EqualFold(v.Name, vaultName) {
			destination = v.ID
			break
		}
	}
	if destination == "" && !opts.DryRun {
		created, err := svc.CreateVault(ctx, ownerID, vault.VaultInput{
			Name:        vaultName,
			Description: "Importado do Google Chrome",
		})
		if err != nil {
			return res, err
		}
		destination = created.ID
	}
	res.VaultID = destination

	// Names already present, so an import never silently overwrites an entry.
	existing := map[string]bool{}
	if destination != "" {
		entries, err := svc.ListEntries(ctx, ownerID, destination)
		if err != nil {
			return res, err
		}
		for _, e := range entries {
			existing[strings.ToLower(e.Path)] = true
		}
	}

	for _, row := range rows[1:] {
		get := func(name string) string {
			i, ok := cols[name]
			if !ok || i >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[i])
		}

		name := get("name")
		rawURL := get("url")
		username := get("username")
		password := get("password")
		note := get("note")

		if password == "" {
			res.Skipped++
			continue
		}
		if name == "" {
			switch {
			case hostOf(rawURL) != "":
				name = hostOf(rawURL)
			case username != "":
				name = username
			default:
				res.Skipped++
				continue
			}
		}
		if existing[strings.ToLower(name)] {
			res.Skipped++
			continue
		}

		metadata := map[string]string{}
		if username != "" {
			metadata["username"] = username
		}
		if rawURL != "" {
			metadata["url"] = rawURL
		}
		if note != "" {
			metadata["note"] = note
		}

		if opts.DryRun {
			existing[strings.ToLower(name)] = true
			res.Imported++
			res.Names = append(res.Names, name)
			continue
		}

		_, err := svc.CreateEntry(ctx, ownerID, vault.EntryInput{
			VaultID:  destination,
			Path:     name,
			Type:     "login",
			Value:    password,
			Metadata: metadata,
			Tags:     []string{"chrome"},
		})
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		existing[strings.ToLower(name)] = true
		res.Imported++
		res.Names = append(res.Names, name)
	}

	return res, nil
}

// hostOf reduces a URL (or bare host) to its hostname without the www. prefix.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
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

// ReadAll drains a reader, guarding against absurd uploads.
func ReadAll(r io.Reader) (string, error) {
	const maxBytes = 8 << 20 // 8 MiB: a Chrome export is far smaller
	data, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
