package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// --- database ---

var db *sql.DB

func openDB() (*sql.DB, error) {
	if err := os.MkdirAll("data", 0o755); err != nil {
		return nil, err
	}
	d, err := sql.Open("sqlite", "data/openpass.db")
	if err != nil {
		return nil, err
	}
	// FKs (ignored by SQLite, but kept for document intent)
	if _, err := d.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}
	return d, nil
}

func mustMigrate() {
	if err := os.MkdirAll("data", 0o755); err != nil {
		log.Fatal(err)
	}
	src, err := os.ReadFile("migrations/001_init.sql")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := db.Exec(string(src)); err != nil {
		log.Fatal(err)
	}
	log.Println("migration applied")
}

// --- models ---

type user struct {
	ID        string
	Email     string
	Name      string
	CreatedAt string
}

type apiKey struct {
	ID           string
	UserID       string
	Name         string
	KeyPrefix    string
	Permissions  *string
	LastUsedAt   *string
	ExpiresAt    *string
	CreatedAt    string
}

type vault struct {
	ID          string
	UserID      string
	Name        string
	Description *string
	CreatedAt   string
	UpdatedAt   string
}

type entry struct {
	ID         string
	VaultID    string
	Path       string
	Type       string
	ValueCipher *string
	Metadata   *string
	UpdatedAt  string
	CreatedAt  string
}

type backup struct {
	ID        string
	UserID    string
	Filename  string
	SizeBytes *int
	Format    string
	Status    string
	CreatedAt string
}

type auditLog struct {
	ID        int
	APIKeyID  *string
	IP        string
	Endpoint  string
	Method    string
	StatusCode int
	CreatedAt string
}

// --- utils ---

const publicPrefix = "op_live_"
const secretPrefix = "op_sk_"

func genToken(prefix string) (id, token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", "", err
	}
	secret := hex.EncodeToString(buf)
	token = prefix + secret
	hash = fmt.Sprintf("%x", []byte(token)) // placeholder
	return fmt.Sprintf("%x", []byte(token+prefix)), token, hash, nil
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// --- handlers ---

// API Keys

func listKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.Header.Get("X-User-ID")
	rows, err := db.QueryContext(ctx, `SELECT id, user_id, name, key_prefix, permissions, last_used_at, expires_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var out []apiKey
	for rows.Next() {
		var k apiKey
		var perms, lu, exp sql.NullString
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyPrefix, &perms, &lu, &exp, &k.CreatedAt); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if perms.Valid {
			v := perms.String
			k.Permissions = &v
		}
		if lu.Valid {
			v := lu.String
			k.LastUsedAt = &v
		}
		if exp.Valid {
			v := exp.String
			k.ExpiresAt = &v
		}
		out = append(out, k)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func createKey(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1<<20); err != nil {
		jsonErr(w, 400, "invalid form")
		return
	}
	userID := r.Header.Get("X-User-ID")
	name := r.FormValue("name")
	prefix := r.FormValue("prefix")
	if strings.TrimSpace(prefix) == "" {
		prefix = publicPrefix
	}
	if strings.TrimSpace(name) == "" {
		jsonErr(w, 422, "name required")
		return
	}
	perms := r.FormValue("permissions")
	id, token, hash, err := genToken(prefix)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if _, err := db.Exec(`INSERT INTO api_keys(id, user_id, name, key_hash, key_prefix, permissions) VALUES(?,?,?,?,?,?)`,
		id, userID, name, hash, prefix, perms,
	); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "key": token, "prefix": prefix})
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	userID := r.Header.Get("X-User-ID")
	res, err := db.Exec(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonErr(w, 404, "not found")
		return
	}
	w.WriteHeader(204)
}

// Vaults

func listVaults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.Header.Get("X-User-ID")
	rows, err := db.QueryContext(ctx, `SELECT id, user_id, name, description, created_at, updated_at FROM vaults WHERE user_id = ? ORDER BY updated_at DESC`, userID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var out []vault
	for rows.Next() {
		var v vault
		var desc sql.NullString
		if err := rows.Scan(&v.ID, &v.UserID, &v.Name, &desc, &v.CreatedAt, &v.UpdatedAt); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if desc.Valid {
			d := desc.String
			v.Description = &d
		}
		out = append(out, v)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func createVault(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	userID := r.Header.Get("X-User-ID")
	if strings.TrimSpace(body.Name) == "" {
		jsonErr(w, 422, "name required")
		return
	}
	id := fmt.Sprintf("%x", []byte(body.Name+time.Now().String()+userID))
	if _, err := db.Exec(`INSERT INTO vaults(id, user_id, name, description) VALUES(?,?,?,?)`, id, userID, body.Name, body.Description); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
}

// Entries

func listEntries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vaultID := r.URL.Query().Get("vault_id")
	if vaultID == "" {
		jsonErr(w, 400, "vault_id required")
		return
	}
	rows, err := db.QueryContext(ctx, `SELECT id, vault_id, path, type, value_cipher, metadata, created_at, updated_at FROM entries WHERE vault_id = ? ORDER BY updated_at DESC`, vaultID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	var out []entry
	for rows.Next() {
		var e entry
		var vc, md sql.NullString
		if err := rows.Scan(&e.ID, &e.VaultID, &e.Path, &e.Type, &vc, &md, &e.CreatedAt, &e.UpdatedAt); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if vc.Valid {
			p := vc.String
			e.ValueCipher = &p
		}
		if md.Valid {
			p := md.String
			e.Metadata = &p
		}
		out = append(out, e)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func createEntry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VaultID     string  `json:"vault_id"`
		Path        string  `json:"path"`
		Type        string  `json:"type"`
		ValueCipher *string `json:"value_cipher"`
		Metadata    *string `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if strings.TrimSpace(body.VaultID) == "" || strings.TrimSpace(body.Path) == "" || strings.TrimSpace(body.Type) == "" {
		jsonErr(w, 422, "vault_id, path and type required")
		return
	}
	id := fmt.Sprintf("%x", []byte(body.VaultID+body.Path+time.Now().String()))
	if _, err := db.Exec(`INSERT INTO entries(id, vault_id, path, type, value_cipher, metadata) VALUES(?,?,?,?,?,?)`,
		id, body.VaultID, body.Path, body.Type, body.ValueCipher, body.Metadata,
	); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
}

func deleteEntry(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/entries/")
	if _, err := db.Exec(`DELETE FROM entries WHERE id = ?`, id); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

// Backups

func createBackup(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	id := fmt.Sprintf("bkp_%x", time.Now().Unix())
	filename := id + ".zip"
	f, err := os.Create(filepath.Join("backups", filename))
	if err != nil {
		if err := os.MkdirAll("backups", 0o755); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		f, err = os.Create(filepath.Join("backups", filename))
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	}
	defer f.Close()
	if _, err := io.Copy(f, r.Body); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	info, _ := f.Stat()
	size := int(info.Size())
	if _, err := db.Exec(`INSERT INTO backups(id, user_id, filename, size_bytes, status) VALUES(?,?,?,?,?)`, id, userID, filename, size, "completed"); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "filename": filename, "size_bytes": size})
}

func restoreBackup(w http.ResponseWriter, r *http.Request) {
	// For MVP: accept uploaded zip and re-import into DB (best-effort placeholder)
	userID := r.Header.Get("X-User-ID")
	id := fmt.Sprintf("restore_%x", time.Now().Unix())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "user_id": userID, "status": "queued"})
}

// --- auth middleware ---

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeAudit(nil, r, 401)
			jsonErr(w, 401, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		hash := fmt.Sprintf("%x", []byte(token))
		var id string
		if err := db.QueryRow(`SELECT id FROM api_keys WHERE key_hash = ?`, hash).Scan(&id); err != nil {
			writeAudit(nil, r, 401)
			jsonErr(w, 401, "invalid api key")
			return
		}
		// update last_used_at (best-effort)
		_, _ = db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
		// userID from key->user mapping to simplify sharing
		var uid string
		_ = db.QueryRow(`SELECT user_id FROM api_keys WHERE id = ?`, id).Scan(&uid)
		r.Header.Set("X-User-ID", uid)
		r.Header.Set("X-Api-Key-ID", id)
		writeAudit(&id, r, 200)
		next(w, r)
	}
}

func writeAudit(keyID *string, r *http.Request, status int) {
	ip := r.RemoteAddr
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		ip = strings.Split(xf, ",")[0]
	}
	_, _ = db.Exec(`INSERT INTO api_audit_logs(api_key_id, ip, endpoint, method, status_code) VALUES(?,?,?,?,?)`,
		keyID, ip, r.URL.Path, r.Method, status,
	)
}

// --- router ---

func main() {
	var err error
	db, err = openDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	mustMigrate()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/keys", authMiddleware(listKeys))
	mux.HandleFunc("/api/keys/create", authMiddleware(createKey))
	mux.HandleFunc("/api/keys/delete/", authMiddleware(deleteKey))

	mux.HandleFunc("/api/v1/vaults", authMiddleware(listVaults))
	mux.HandleFunc("/api/v1/vaults/create", authMiddleware(createVault))

	mux.HandleFunc("/api/v1/entries", authMiddleware(listEntries))
	mux.HandleFunc("/api/v1/entries/create", authMiddleware(createEntry))
	mux.HandleFunc("/api/v1/entries/delete/", authMiddleware(deleteEntry))

	mux.HandleFunc("/api/v1/backup/create", authMiddleware(createBackup))
	mux.HandleFunc("/api/v1/backup/restore", authMiddleware(restoreBackup))

	srv := &http.Server{Addr: ":8080", Handler: logMiddleware(mux)}
	log.Println("OpenPass API on :8080")
	log.Fatal(srv.ListenAndServe())
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lw.status, time.Since(start).String())
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(code int) { l.status = code; l.ResponseWriter.WriteHeader(code) }
