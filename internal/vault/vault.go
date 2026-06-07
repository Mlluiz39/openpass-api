package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/openpass/api/internal/apikeys"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

var ErrForbidden = errors.New("forbidden")

type Service struct {
	db  *sql.DB
	box secure.Box
}

type VaultInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Vault struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type EntryInput struct {
	VaultID  string            `json:"vault_id"`
	Path     string            `json:"path"`
	Type     string            `json:"type"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata"`
	Tags     []string          `json:"tags"`
}

type Entry struct {
	ID        string            `json:"id"`
	VaultID   string            `json:"vault_id"`
	Path      string            `json:"path"`
	Type      string            `json:"type"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

func New(database *sql.DB, secret string) *Service {
	return &Service{db: database, box: secure.NewBox(secret)}
}

func (s *Service) CreateVault(ctx context.Context, input VaultInput) (Vault, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Vault{}, errors.New("name required")
	}
	id, err := randomID()
	if err != nil {
		return Vault{}, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vaults(id, name, description) VALUES(?,?,?)`, id, name, strings.TrimSpace(input.Description)); err != nil {
		return Vault{}, err
	}
	return s.getVault(ctx, id)
}

func (s *Service) UpdateVault(ctx context.Context, id string, input VaultInput) (Vault, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Vault{}, errors.New("name required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE vaults SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		name, strings.TrimSpace(input.Description), id,
	)
	if err != nil {
		return Vault{}, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return Vault{}, sql.ErrNoRows
	}
	return s.getVault(ctx, id)
}

func (s *Service) DeleteVault(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vaults WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Service) ListVaults(ctx context.Context, key *apikeys.AuthenticatedKey) ([]Vault, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM vaults`
	args := []any{}
	if key != nil && len(key.VaultScope) > 0 {
		placeholders := make([]string, 0, len(key.VaultScope))
		for _, id := range key.VaultScope {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query += ` WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vault
	for rows.Next() {
		v, err := scanVault(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Service) CreateEntry(ctx context.Context, input EntryInput) (Entry, error) {
	if strings.TrimSpace(input.VaultID) == "" || strings.TrimSpace(input.Path) == "" || strings.TrimSpace(input.Type) == "" {
		return Entry{}, errors.New("vault_id, path and type required")
	}
	id, err := randomID()
	if err != nil {
		return Entry{}, err
	}
	encrypted, err := s.box.EncryptString(input.Value)
	if err != nil {
		return Entry{}, err
	}
	metadata, err := marshalOptionalObject(input.Metadata)
	if err != nil {
		return Entry{}, err
	}
	tags, err := marshalOptionalList(input.Tags)
	if err != nil {
		return Entry{}, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO entries(id, vault_id, path, type, encrypted_value, metadata, tags) VALUES(?,?,?,?,?,?,?)`,
		id, input.VaultID, strings.TrimSpace(input.Path), strings.TrimSpace(input.Type), encrypted, metadata, tags,
	); err != nil {
		return Entry{}, err
	}
	return s.getEntry(ctx, id)
}

func (s *Service) UpdateEntry(ctx context.Context, id string, input EntryInput) (Entry, error) {
	encrypted, err := s.box.EncryptString(input.Value)
	if err != nil {
		return Entry{}, err
	}
	metadata, err := marshalOptionalObject(input.Metadata)
	if err != nil {
		return Entry{}, err
	}
	tags, err := marshalOptionalList(input.Tags)
	if err != nil {
		return Entry{}, err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE entries SET path = ?, type = ?, encrypted_value = ?, metadata = ?, tags = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		strings.TrimSpace(input.Path), strings.TrimSpace(input.Type), encrypted, metadata, tags, id,
	)
	if err != nil {
		return Entry{}, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return Entry{}, sql.ErrNoRows
	}
	return s.getEntry(ctx, id)
}

func (s *Service) DeleteEntry(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM entries WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Service) ListEntries(ctx context.Context, vaultID string) ([]Entry, error) {
	query := `SELECT id, vault_id, path, type, metadata, tags, created_at, updated_at FROM entries`
	args := []any{}
	if strings.TrimSpace(vaultID) != "" {
		query += ` WHERE vault_id = ?`
		args = append(args, vaultID)
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, rows.Err()
}

func (s *Service) ListEntriesForAPI(ctx context.Context, key *apikeys.AuthenticatedKey, vaultID string) ([]Entry, error) {
	if key != nil && vaultID != "" && !key.CanAccessVault(vaultID) {
		return nil, ErrForbidden
	}
	if key != nil && vaultID == "" && len(key.VaultScope) > 0 {
		query := `SELECT id, vault_id, path, type, metadata, tags, created_at, updated_at FROM entries WHERE vault_id IN (`
		args := []any{}
		placeholders := make([]string, 0, len(key.VaultScope))
		for _, id := range key.VaultScope {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query += strings.Join(placeholders, ",") + `) ORDER BY updated_at DESC`
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []Entry
		for rows.Next() {
			entry, err := scanEntry(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		return out, rows.Err()
	}
	return s.ListEntries(ctx, vaultID)
}

func (s *Service) RevealEntry(ctx context.Context, id string) (string, error) {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_value FROM entries WHERE id = ?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	return s.box.DecryptString(encrypted)
}

func (s *Service) RegisterAdminRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/vaults", require(http.HandlerFunc(s.AdminListVaults)))
	mux.Handle("POST /api/admin/vaults", require(http.HandlerFunc(s.AdminCreateVault)))
	mux.Handle("PUT /api/admin/vaults/{id}", require(http.HandlerFunc(s.AdminUpdateVault)))
	mux.Handle("DELETE /api/admin/vaults/{id}", require(http.HandlerFunc(s.AdminDeleteVault)))
	mux.Handle("GET /api/admin/entries", require(http.HandlerFunc(s.AdminListEntries)))
	mux.Handle("POST /api/admin/entries", require(http.HandlerFunc(s.AdminCreateEntry)))
	mux.Handle("PUT /api/admin/entries/{id}", require(http.HandlerFunc(s.AdminUpdateEntry)))
	mux.Handle("DELETE /api/admin/entries/{id}", require(http.HandlerFunc(s.AdminDeleteEntry)))
	mux.Handle("GET /api/admin/entries/{id}/reveal", require(http.HandlerFunc(s.AdminRevealEntry)))
}

func (s *Service) RegisterAPIRoutes(mux *http.ServeMux, keys *apikeys.Service) {
	mux.Handle("GET /api/v1/vaults", keys.RequirePermission("vaults:read", http.HandlerFunc(s.APIListVaults)))
	mux.Handle("GET /api/v1/vaults/{id}", keys.RequirePermission("vaults:read", http.HandlerFunc(s.APIGetVault)))
	mux.Handle("GET /api/v1/entries", keys.RequirePermission("entries:read", http.HandlerFunc(s.APIListEntries)))
	mux.Handle("GET /api/v1/entries/{id}", keys.RequirePermission("entries:read", http.HandlerFunc(s.APIGetEntry)))
	mux.Handle("POST /api/v1/entries", keys.RequirePermission("entries:write", http.HandlerFunc(s.APICreateEntry)))
	mux.Handle("PUT /api/v1/entries/{id}", keys.RequirePermission("entries:write", http.HandlerFunc(s.APIUpdateEntry)))
	mux.Handle("DELETE /api/v1/entries/{id}", keys.RequirePermission("entries:write", http.HandlerFunc(s.APIDeleteEntry)))
}

func (s *Service) AdminListVaults(w http.ResponseWriter, r *http.Request) {
	vaults, err := s.ListVaults(r.Context(), nil)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_vaults_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": vaults})
}

func (s *Service) AdminCreateVault(w http.ResponseWriter, r *http.Request) {
	var input VaultInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	v, err := s.CreateVault(r.Context(), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, v)
}

func (s *Service) AdminUpdateVault(w http.ResponseWriter, r *http.Request) {
	var input VaultInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	v, err := s.UpdateVault(r.Context(), r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, v)
}

func (s *Service) AdminDeleteVault(w http.ResponseWriter, r *http.Request) {
	if err := s.DeleteVault(r.Context(), r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) AdminListEntries(w http.ResponseWriter, r *http.Request) {
	entries, err := s.ListEntries(r.Context(), r.URL.Query().Get("vault_id"))
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_entries_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": entries})
}

func (s *Service) AdminCreateEntry(w http.ResponseWriter, r *http.Request) {
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.CreateEntry(r.Context(), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, entry)
}

func (s *Service) AdminUpdateEntry(w http.ResponseWriter, r *http.Request) {
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.UpdateEntry(r.Context(), r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, entry)
}

func (s *Service) AdminDeleteEntry(w http.ResponseWriter, r *http.Request) {
	if err := s.DeleteEntry(r.Context(), r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) AdminRevealEntry(w http.ResponseWriter, r *http.Request) {
	value, err := s.RevealEntry(r.Context(), r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"value": value})
}

func (s *Service) APIListVaults(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	vaults, err := s.ListVaults(r.Context(), key)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_vaults_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": vaults})
}

func (s *Service) APIGetVault(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	id := r.PathValue("id")
	if key != nil && !key.CanAccessVault(id) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	v, err := s.getVault(r.Context(), id)
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, v)
}

func (s *Service) APIListEntries(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	entries, err := s.ListEntriesForAPI(r.Context(), key, r.URL.Query().Get("vault_id"))
	if err == ErrForbidden {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_entries_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": entries})
}

func (s *Service) APIGetEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	entry, err := s.getEntry(r.Context(), r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if key != nil && !key.CanAccessVault(entry.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	value, err := s.RevealEntry(r.Context(), entry.ID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "reveal_entry_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"entry": entry, "value": value})
}

func (s *Service) APICreateEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if key != nil && !key.CanAccessVault(input.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	entry, err := s.CreateEntry(r.Context(), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, entry)
}

func (s *Service) APIUpdateEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	existing, err := s.getEntry(r.Context(), r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if key != nil && !key.CanAccessVault(existing.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.UpdateEntry(r.Context(), r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, entry)
}

func (s *Service) APIDeleteEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	existing, err := s.getEntry(r.Context(), r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if key != nil && !key.CanAccessVault(existing.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.DeleteEntry(r.Context(), existing.ID); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) getVault(ctx context.Context, id string) (Vault, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM vaults WHERE id = ?`, id)
	return scanVault(row)
}

func (s *Service) getEntry(ctx context.Context, id string) (Entry, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, vault_id, path, type, metadata, tags, created_at, updated_at FROM entries WHERE id = ?`, id)
	return scanEntry(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanVault(row scanner) (Vault, error) {
	var v Vault
	var description sql.NullString
	if err := row.Scan(&v.ID, &v.Name, &description, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return Vault{}, err
	}
	v.Description = description.String
	return v, nil
}

func scanEntry(row scanner) (Entry, error) {
	var entry Entry
	var metadataRaw, tagsRaw sql.NullString
	if err := row.Scan(&entry.ID, &entry.VaultID, &entry.Path, &entry.Type, &metadataRaw, &tagsRaw, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
		return Entry{}, err
	}
	entry.Metadata = unmarshalObject(metadataRaw.String)
	entry.Tags = unmarshalList(tagsRaw.String)
	return entry, nil
}

func marshalOptionalObject(value map[string]string) (*string, error) {
	if len(value) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	out := string(raw)
	return &out, nil
}

func marshalOptionalList(values []string) (*string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	out := string(raw)
	return &out, nil
}

func unmarshalObject(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out map[string]string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func unmarshalList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
