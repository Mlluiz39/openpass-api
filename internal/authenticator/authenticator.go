// Package authenticator serves the TOTP (2FA) codes for entries that carry an
// authenticator secret, and generates random passwords.
//
// It deliberately reads and writes through vault.Service rather than touching
// the entries table on its own, so ownership rules, the encryption box and the
// uniqueness constraints all stay in one place.
package authenticator

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/apikeys"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/password"
	"github.com/openpass/api/internal/secure"
	"github.com/openpass/api/internal/totp"
	"github.com/openpass/api/internal/vault"
)

var (
	// ErrNoSecret means the entry exists but has no authenticator secret.
	ErrNoSecret = errors.New("totp não configurado para este item")
	// ErrInvalidSecret means the supplied secret is not usable base32/otpauth.
	ErrInvalidSecret = errors.New("segredo TOTP inválido")
)

// Service exposes 2FA codes and password generation to the panel and the API.
type Service struct {
	db  *sql.DB
	svc *vault.Service
	box secure.Box
}

// New wires the authenticator to the database, the vault service and the same
// encryption box the vault uses.
func New(db *sql.DB, vaultSvc *vault.Service, box secure.Box) *Service {
	return &Service{db: db, svc: vaultSvc, box: box}
}

// RegisterAdminRoutes mounts the session (panel) endpoints.
func (s *Service) RegisterAdminRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("PUT /api/admin/entries/{id}/totp", require(http.HandlerFunc(s.AdminSetSecret)))
	mux.Handle("GET /api/admin/entries/{id}/code", require(http.HandlerFunc(s.AdminCurrentCode)))
	mux.Handle("GET /api/admin/password/generate", require(http.HandlerFunc(s.AdminGeneratePassword)))
}

// RegisterAPIRoutes mounts the API-key endpoints, so the browser extension can
// fetch a code for an item the user is looking at.
func (s *Service) RegisterAPIRoutes(mux *http.ServeMux, keys *apikeys.Service) {
	mux.Handle("GET /api/v1/entries/{id}/code", keys.RequirePermission("entries:read", http.HandlerFunc(s.APICurrentCode)))
	mux.Handle("POST /api/v1/password/generate", keys.RequirePermission("entries:write", http.HandlerFunc(s.APIGeneratePassword)))
}

// ---------------------------------------------------------------- operations

// SetSecret validates and stores an entry's authenticator secret.
//
// The secret is encrypted with the app key like any other value: it is a
// credential in its own right, so storing it in plaintext would defeat the
// vault. An empty secret clears the entry instead.
func (s *Service) SetSecret(ctx context.Context, ownerID, entryID, secret string) error {
	secret = strings.TrimSpace(secret)

	if secret == "" {
		res, err := s.db.ExecContext(ctx, `UPDATE entries SET encrypted_totp = NULL, updated_at = $1
			WHERE id = $2 AND vault_id IN (SELECT id FROM vaults WHERE owner_id = $3)`,
			now(), entryID, ownerID)
		if err != nil {
			return err
		}
		return notFoundIfNoRows(res)
	}

	if err := totp.Validate(secret); err != nil {
		return ErrInvalidSecret
	}
	encrypted, err := s.box.EncryptString(secret)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE entries SET encrypted_totp = $1, updated_at = $2
		WHERE id = $3 AND vault_id IN (SELECT id FROM vaults WHERE owner_id = $4)`,
		encrypted, now(), entryID, ownerID)
	if err != nil {
		return err
	}
	return notFoundIfNoRows(res)
}

// ClearSecret forgets an entry's authenticator secret.
func (s *Service) ClearSecret(ctx context.Context, ownerID, entryID string) error {
	return s.SetSecret(ctx, ownerID, entryID, "")
}

// HasSecret reports whether an entry carries an authenticator secret.
func (s *Service) HasSecret(ctx context.Context, ownerID, entryID string) (bool, error) {
	var encrypted sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT e.encrypted_totp FROM entries e
		JOIN vaults v ON v.id = e.vault_id WHERE e.id = $1 AND v.owner_id = $2`,
		entryID, ownerID).Scan(&encrypted)
	if err != nil {
		return false, err
	}
	return encrypted.Valid && encrypted.String != "", nil
}

// Code decrypts an entry's secret and returns the one-time password valid now.
func (s *Service) Code(ctx context.Context, ownerID, entryID string) (totp.Code, error) {
	var encrypted sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT e.encrypted_totp FROM entries e
		JOIN vaults v ON v.id = e.vault_id WHERE e.id = $1 AND v.owner_id = $2`,
		entryID, ownerID).Scan(&encrypted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return totp.Code{}, vault.ErrForbidden
		}
		return totp.Code{}, err
	}
	if !encrypted.Valid || encrypted.String == "" {
		return totp.Code{}, ErrNoSecret
	}

	secret, err := s.box.DecryptString(encrypted.String)
	if err != nil {
		return totp.Code{}, err
	}
	cfg, err := totp.Parse(secret)
	if err != nil {
		return totp.Code{}, ErrInvalidSecret
	}
	return totp.Generate(cfg, time.Now().UTC())
}

// ------------------------------------------------------------------ session

// AdminSetSecret handles PUT /api/admin/entries/{id}/totp.
func (s *Service) AdminSetSecret(w http.ResponseWriter, r *http.Request) {
	user, ok := admin.FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var input struct {
		Secret string `json:"secret"`
	}
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if err := s.SetSecret(r.Context(), user.ID, r.PathValue("id"), input.Secret); err != nil {
		switch {
		case errors.Is(err, ErrInvalidSecret):
			httpjson.Error(w, http.StatusBadRequest, "segredo TOTP inválido")
		case errors.Is(err, vault.ErrForbidden):
			httpjson.Error(w, http.StatusNotFound, "not_found")
		default:
			httpjson.Error(w, http.StatusInternalServerError, "set_totp_failed")
		}
		return
	}

	enabled, err := s.HasSecret(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "set_totp_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"has_totp": enabled})
}

// AdminCurrentCode handles GET /api/admin/entries/{id}/code.
func (s *Service) AdminCurrentCode(w http.ResponseWriter, r *http.Request) {
	user, ok := admin.FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	code, err := s.Code(r.Context(), user.ID, r.PathValue("id"))
	if errors.Is(err, ErrNoSecret) {
		httpjson.Error(w, http.StatusNotFound, "totp_not_configured")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "totp_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, code)
}

// AdminGeneratePassword handles GET /api/admin/password/generate.
func (s *Service) AdminGeneratePassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := admin.FromContext(r.Context()); !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	value, err := password.Generate(optionsFromQuery(r))
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"password": value,
		"strength": int(password.Strength(value)),
	})
}

// ------------------------------------------------------------------- API key

// APICurrentCode handles GET /api/v1/entries/{id}/code.
func (s *Service) APICurrentCode(w http.ResponseWriter, r *http.Request) {
	key, ok := apikeys.FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	entry, err := s.svc.GetEntry(r.Context(), key.OwnerID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if !key.CanAccessVault(entry.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}

	code, err := s.Code(r.Context(), key.OwnerID, entry.ID)
	if errors.Is(err, ErrNoSecret) {
		httpjson.Error(w, http.StatusNotFound, "totp_not_configured")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "totp_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, code)
}

// APIGeneratePassword handles POST /api/v1/password/generate.
func (s *Service) APIGeneratePassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := apikeys.FromContext(r.Context()); !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	options := password.DefaultOptions()
	// A body is optional: without one the defaults above are used.
	if r.ContentLength > 0 {
		var body struct {
			Length           *int  `json:"length"`
			Lower            *bool `json:"lower"`
			Upper            *bool `json:"upper"`
			Digits           *bool `json:"digits"`
			Symbols          *bool `json:"symbols"`
			ExcludeAmbiguous *bool `json:"exclude_ambiguous"`
		}
		if err := httpjson.Decode(r, &body); err == nil {
			if body.Length != nil {
				options.Length = *body.Length
			}
			if body.Lower != nil {
				options.Lower = *body.Lower
			}
			if body.Upper != nil {
				options.Upper = *body.Upper
			}
			if body.Digits != nil {
				options.Digits = *body.Digits
			}
			if body.Symbols != nil {
				options.Symbols = *body.Symbols
			}
			if body.ExcludeAmbiguous != nil {
				options.ExcludeAmbiguous = *body.ExcludeAmbiguous
			}
		}
	}

	value, err := password.Generate(options)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"password": value,
		"strength": int(password.Strength(value)),
	})
}

// ------------------------------------------------------------------- helpers

func optionsFromQuery(r *http.Request) password.Options {
	q := r.URL.Query()
	return password.Options{
		Length:           atoiDefault(q.Get("length"), 20),
		Lower:            boolDefault(q.Get("lower"), true),
		Upper:            boolDefault(q.Get("upper"), true),
		Digits:           boolDefault(q.Get("digits"), true),
		Symbols:          boolDefault(q.Get("symbols"), true),
		ExcludeAmbiguous: boolDefault(q.Get("exclude_ambiguous"), false),
	}
}

func atoiDefault(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
		if n > 1000 {
			return fallback
		}
	}
	return n
}

func boolDefault(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func notFoundIfNoRows(res sql.Result) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		// Zero rows means the entry is not the caller's (or is gone); both map
		// to 404 so a foreign ID is indistinguishable from a missing one.
		return vault.ErrForbidden
	}
	return nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
