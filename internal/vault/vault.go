package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/apikeys"
	opdb "github.com/openpass/api/internal/db"
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

func (s *Service) CreateVault(ctx context.Context, ownerID string, input VaultInput) (Vault, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Vault{}, errors.New("name required")
	}
	id, err := randomID()
	if err != nil {
		return Vault{}, err
	}
	now := nowRFC3339()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO vaults(id, owner_id, name, description, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6)`,
		id, ownerID, name, strings.TrimSpace(input.Description), now, now,
	); err != nil {
		return Vault{}, err
	}
	return s.getVault(ctx, ownerID, id)
}

func (s *Service) UpdateVault(ctx context.Context, ownerID, id string, input VaultInput) (Vault, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return Vault{}, errors.New("name required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE vaults SET name = $1, description = $2, updated_at = $3 WHERE id = $4 AND owner_id = $5`,
		name, strings.TrimSpace(input.Description), nowRFC3339(), id, ownerID,
	)
	if err != nil {
		return Vault{}, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return Vault{}, sql.ErrNoRows
	}
	return s.getVault(ctx, ownerID, id)
}

func (s *Service) DeleteVault(ctx context.Context, ownerID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vaults WHERE id = $1 AND owner_id = $2`, id, ownerID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListVaults returns the owner's vaults, optionally narrowed to an API key's
// vault scope. ownerID is always applied first: a key can only ever restrict
// within its owner's data, never widen it.
func (s *Service) ListVaults(ctx context.Context, ownerID string, scope []string) ([]Vault, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM vaults WHERE owner_id = $1`
	args := []any{ownerID}
	if len(scope) > 0 {
		placeholders := make([]string, 0, len(scope))
		for _, id := range scope {
			args = append(args, id)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		query += ` AND id IN (` + strings.Join(placeholders, ",") + `)`
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

func (s *Service) CreateEntry(ctx context.Context, ownerID string, input EntryInput) (Entry, error) {
	path := strings.TrimSpace(input.Path)
	if path == "" {
		return Entry{}, errors.New("path required")
	}
	entryType := strings.TrimSpace(input.Type)
	if entryType == "" {
		entryType = "login"
	}
	vaultID := strings.TrimSpace(input.VaultID)
	if vaultID == "" {
		// No vault given: fall back to the owner's oldest vault, creating the
		// default "Principal" vault on first use.
		err := s.db.QueryRowContext(ctx, `SELECT id FROM vaults WHERE owner_id = $1 ORDER BY created_at ASC LIMIT 1`, ownerID).Scan(&vaultID)
		if err == sql.ErrNoRows {
			v, err := s.CreateVault(ctx, ownerID, VaultInput{Name: "Principal", Description: "Cofre principal"})
			if err != nil {
				return Entry{}, err
			}
			vaultID = v.ID
		} else if err != nil {
			return Entry{}, err
		}
	} else if !s.ownsVault(ctx, ownerID, vaultID) {
		return Entry{}, ErrForbidden
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
	now := nowRFC3339()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO entries(id, vault_id, path, type, encrypted_value, metadata, tags, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, vaultID, path, entryType, encrypted, metadata, tags, now, now,
	); err != nil {
		if opdb.IsUniqueViolation(err) {
			return Entry{}, errors.New("já existe um item com este nome")
		}
		return Entry{}, err
	}
	return s.getEntry(ctx, ownerID, id)
}

func (s *Service) UpdateEntry(ctx context.Context, ownerID, id string, input EntryInput) (Entry, error) {
	path := strings.TrimSpace(input.Path)
	if path == "" {
		return Entry{}, errors.New("path required")
	}
	entryType := strings.TrimSpace(input.Type)
	if entryType == "" {
		entryType = "login"
	}
	metadata, err := marshalOptionalObject(input.Metadata)
	if err != nil {
		return Entry{}, err
	}
	tags, err := marshalOptionalList(input.Tags)
	if err != nil {
		return Entry{}, err
	}

	// Ownership first: the UPDATE itself is restricted to entries whose vault
	// belongs to ownerID, so a guessed ID can never be modified cross-user.
	var res sql.Result
	now := nowRFC3339()
	if strings.TrimSpace(input.Value) != "" {
		// encErr, not err: a := here would shadow the outer err and the
		// ExecContext failure below would be silently swallowed (and res
		// would stay nil for RowsAffected).
		encrypted, encErr := s.box.EncryptString(input.Value)
		if encErr != nil {
			return Entry{}, encErr
		}
		res, err = s.db.ExecContext(ctx, `UPDATE entries SET path = $1, type = $2, encrypted_value = $3, metadata = $4, tags = $5, updated_at = $6
			WHERE id = $7 AND vault_id IN (SELECT id FROM vaults WHERE owner_id = $8)`,
			path, entryType, encrypted, metadata, tags, now, id, ownerID,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE entries SET path = $1, type = $2, metadata = $3, tags = $4, updated_at = $5
			WHERE id = $6 AND vault_id IN (SELECT id FROM vaults WHERE owner_id = $7)`,
			path, entryType, metadata, tags, now, id, ownerID,
		)
	}
	if err != nil {
		if opdb.IsUniqueViolation(err) {
			return Entry{}, errors.New("já existe um item com este nome")
		}
		return Entry{}, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return Entry{}, sql.ErrNoRows
	}
	return s.getEntry(ctx, ownerID, id)
}

func (s *Service) DeleteEntry(ctx context.Context, ownerID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM entries
		WHERE id = $1 AND vault_id IN (SELECT id FROM vaults WHERE owner_id = $2)`, id, ownerID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListEntries returns the owner's entries, optionally for a single vault.
func (s *Service) ListEntries(ctx context.Context, ownerID, vaultID string) ([]Entry, error) {
	return s.listEntries(ctx, ownerID, vaultID, nil)
}

// ListEntriesForAPI applies the API key's vault scope on top of the key
// owner's data: an empty scope means "everything the owner has".
func (s *Service) ListEntriesForAPI(ctx context.Context, key *apikeys.AuthenticatedKey, vaultID string) ([]Entry, error) {
	if key == nil {
		return nil, ErrForbidden
	}
	if vaultID != "" && !key.CanAccessVault(vaultID) {
		return nil, ErrForbidden
	}
	return s.listEntries(ctx, key.OwnerID, vaultID, key.VaultScope)
}

func (s *Service) listEntries(ctx context.Context, ownerID, vaultID string, scope []string) ([]Entry, error) {
	query := `SELECT e.id, e.vault_id, e.path, e.type, e.metadata, e.tags, e.created_at, e.updated_at
		FROM entries e JOIN vaults v ON v.id = e.vault_id WHERE v.owner_id = $1`
	args := []any{ownerID}
	if strings.TrimSpace(vaultID) != "" {
		args = append(args, vaultID)
		query += fmt.Sprintf(` AND e.vault_id = $%d`, len(args))
	} else if len(scope) > 0 {
		placeholders := make([]string, 0, len(scope))
		for _, id := range scope {
			args = append(args, id)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		query += ` AND e.vault_id IN (` + strings.Join(placeholders, ",") + `)`
	}
	query += ` ORDER BY e.updated_at DESC`
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

// RevealEntry decrypts an entry's value only when the entry belongs to
// ownerID; otherwise sql.ErrNoRows is returned (callers map it to 404, so a
// foreign ID is indistinguishable from a missing one).
func (s *Service) RevealEntry(ctx context.Context, ownerID, id string) (string, error) {
	var encrypted string
	err := s.db.QueryRowContext(ctx, `SELECT e.encrypted_value
		FROM entries e JOIN vaults v ON v.id = e.vault_id
		WHERE e.id = $1 AND v.owner_id = $2`, id, ownerID).Scan(&encrypted)
	if err != nil {
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

// requestUser returns the session user injected by admin.Require. A missing
// user would be a wiring bug (route registered without Require), so handlers
// fail closed.
func requestUser(r *http.Request) (*admin.CurrentUser, bool) {
	return admin.FromContext(r.Context())
}

func (s *Service) AdminListVaults(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	vaults, err := s.ListVaults(r.Context(), user.ID, nil)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_vaults_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": vaults})
}

func (s *Service) AdminCreateVault(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input VaultInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	v, err := s.CreateVault(r.Context(), user.ID, input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, v)
}

func (s *Service) AdminUpdateVault(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input VaultInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	v, err := s.UpdateVault(r.Context(), user.ID, r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, v)
}

func (s *Service) AdminDeleteVault(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.DeleteVault(r.Context(), user.ID, r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) AdminListEntries(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	entries, err := s.ListEntries(r.Context(), user.ID, r.URL.Query().Get("vault_id"))
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_entries_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": entries})
}

func (s *Service) AdminCreateEntry(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.CreateEntry(r.Context(), user.ID, input)
	if err == ErrForbidden {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, entry)
}

func (s *Service) AdminUpdateEntry(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.UpdateEntry(r.Context(), user.ID, r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, entry)
}

func (s *Service) AdminDeleteEntry(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := s.DeleteEntry(r.Context(), user.ID, r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) AdminRevealEntry(w http.ResponseWriter, r *http.Request) {
	user, ok := requestUser(r)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	value, err := s.RevealEntry(r.Context(), user.ID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"value": value})
}

func (s *Service) APIListVaults(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	vaults, err := s.ListVaults(r.Context(), key.OwnerID, key.VaultScope)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_vaults_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": vaults})
}

func (s *Service) APIGetVault(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	id := r.PathValue("id")
	if !key.CanAccessVault(id) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	v, err := s.getVault(r.Context(), key.OwnerID, id)
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
	entry, err := s.getEntry(r.Context(), key.OwnerID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if !key.CanAccessVault(entry.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	value, err := s.RevealEntry(r.Context(), key.OwnerID, entry.ID)
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
	if !key.CanAccessVault(input.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	entry, err := s.CreateEntry(r.Context(), key.OwnerID, input)
	if err == ErrForbidden {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, entry)
}

func (s *Service) APIUpdateEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	existing, err := s.getEntry(r.Context(), key.OwnerID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if !key.CanAccessVault(existing.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	var input EntryInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	entry, err := s.UpdateEntry(r.Context(), key.OwnerID, r.PathValue("id"), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, entry)
}

func (s *Service) APIDeleteEntry(w http.ResponseWriter, r *http.Request) {
	key, _ := apikeys.FromContext(r.Context())
	existing, err := s.getEntry(r.Context(), key.OwnerID, r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if !key.CanAccessVault(existing.VaultID) {
		httpjson.Error(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := s.DeleteEntry(r.Context(), key.OwnerID, existing.ID); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) ownsVault(ctx context.Context, ownerID, vaultID string) bool {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM vaults WHERE id = $1 AND owner_id = $2`, vaultID, ownerID).Scan(&one)
	return err == nil
}

func (s *Service) getVault(ctx context.Context, ownerID, id string) (Vault, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, description, created_at, updated_at FROM vaults WHERE id = $1 AND owner_id = $2`, id, ownerID)
	return scanVault(row)
}

func (s *Service) getEntry(ctx context.Context, ownerID, id string) (Entry, error) {
	row := s.db.QueryRowContext(ctx, `SELECT e.id, e.vault_id, e.path, e.type, e.metadata, e.tags, e.created_at, e.updated_at
		FROM entries e JOIN vaults v ON v.id = e.vault_id
		WHERE e.id = $1 AND v.owner_id = $2`, id, ownerID)
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

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
