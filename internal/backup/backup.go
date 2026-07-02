package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

const (
	FormatVersion    = "openpass.backup.v1"
	MIMEType         = "application/vnd.openpass.backup+json"
	BackupKDF        = "pbkdf2-sha256"
	BackupIterations = 600000
	backupSaltBytes  = 16
	backupKeyBytes   = 32
)

var backupTables = []string{
	"api_keys",
	"vaults",
	"entries",
	"backups",
	"api_audit_logs",
}

var restoreDeleteOrder = []string{
	"api_audit_logs",
	"backups",
	"entries",
	"vaults",
	"api_keys",
}

var restoreInsertOrder = []string{
	"api_keys",
	"vaults",
	"entries",
	"backups",
	"api_audit_logs",
}

type Service struct {
	db        *sql.DB
	appSecret string
}

type File struct {
	Filename string
	Content  []byte
}

type document struct {
	Format    string                      `json:"format"`
	CreatedAt string                      `json:"created_at"`
	Tables    map[string][]map[string]any `json:"tables"`
	Counts    map[string]int              `json:"counts"`
	Meta      map[string]string           `json:"meta"`
}

type encryptedDocument struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	CreatedAt  string `json:"created_at"`
	KDF        string `json:"kdf,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Ciphertext string `json:"ciphertext"`
}

func New(database *sql.DB, appSecret string) *Service {
	return &Service{db: database, appSecret: appSecret}
}

func (s *Service) Export(ctx context.Context, password string) (File, error) {
	doc, err := s.collect(ctx)
	if err != nil {
		return File{}, err
	}
	plaintext, err := json.Marshal(doc)
	if err != nil {
		return File{}, err
	}
	salt := make([]byte, backupSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return File{}, err
	}
	key := pbkdf2Key([]byte(s.passphrase(password)), salt, BackupIterations, backupKeyBytes, sha256.New)
	ciphertext, err := encryptWithKey(key, string(plaintext))
	if err != nil {
		return File{}, err
	}
	envelope := encryptedDocument{
		Format:     FormatVersion,
		Version:    1,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		KDF:        BackupKDF,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Iterations: BackupIterations,
		Ciphertext: ciphertext,
	}
	content, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return File{}, err
	}
	filename := "openpass-backup-" + time.Now().UTC().Format("20060102-150405") + ".opbackup"
	_ = s.record(ctx, filename, len(content), "exported")
	return File{Filename: filename, Content: content}, nil
}

func (s *Service) Restore(ctx context.Context, content []byte, password string) error {
	var envelope encryptedDocument
	if err := json.Unmarshal(bytes.TrimSpace(content), &envelope); err != nil {
		return err
	}
	if envelope.Format != FormatVersion || envelope.Ciphertext == "" {
		return errors.New("invalid backup format")
	}
	plaintext, err := s.decryptEnvelope(envelope, password)
	if err != nil {
		return err
	}
	var doc document
	if err := json.Unmarshal([]byte(plaintext), &doc); err != nil {
		return err
	}
	if doc.Format != FormatVersion {
		return errors.New("invalid backup payload")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, table := range restoreDeleteOrder {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	for _, table := range restoreInsertOrder {
		rows := doc.Tables[table]
		if len(rows) == 0 {
			continue
		}
		columns, err := tableColumns(ctx, tx, table)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := insertRow(ctx, tx, table, columns, row); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.record(ctx, "restore-"+time.Now().UTC().Format("20060102-150405"), len(content), "restored")
}

func (s *Service) RegisterAdminRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/backups", require(http.HandlerFunc(s.ListHandler)))
	mux.Handle("DELETE /api/admin/backups", require(http.HandlerFunc(s.ClearHistoryHandler)))
	mux.Handle("POST /api/admin/backup/export", require(http.HandlerFunc(s.ExportHandler)))
	mux.Handle("POST /api/admin/backup/restore", require(http.HandlerFunc(s.RestoreHandler)))
}

func (s *Service) ExportHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if r.Body != nil {
		_ = httpjson.Decode(r, &body)
	}
	file, err := s.Export(r.Context(), body.Password)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "backup_export_failed")
		return
	}
	w.Header().Set("Content-Type", MIMEType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(file.Content)
}

func (s *Service) RestoreHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Backup   string `json:"backup"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if strings.TrimSpace(body.Backup) == "" {
		httpjson.Error(w, http.StatusBadRequest, "backup_required")
		return
	}
	if err := s.Restore(r.Context(), []byte(body.Backup), body.Password); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "backup_restore_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"restored": true})
}

func (s *Service) ListHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT id, filename, size_bytes, format, status, created_at FROM backups ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_backups_failed")
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, filename, format, status, createdAt string
		var size sql.NullInt64
		if err := rows.Scan(&id, &filename, &size, &format, &status, &createdAt); err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "list_backups_failed")
			return
		}
		out = append(out, map[string]any{
			"id":         id,
			"filename":   filename,
			"size_bytes": size.Int64,
			"format":     format,
			"status":     status,
			"created_at": createdAt,
		})
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Service) ClearHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.ClearHistory(r.Context()); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "clear_backup_history_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Service) ClearHistory(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM backups`)
	return err
}

func (s *Service) collect(ctx context.Context) (document, error) {
	doc := document{
		Format:    FormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Tables:    map[string][]map[string]any{},
		Counts:    map[string]int{},
		Meta:      map[string]string{"source": "openpass"},
	}
	for _, table := range backupTables {
		rows, err := s.db.QueryContext(ctx, "SELECT * FROM "+table)
		if err != nil {
			return document{}, err
		}
		tableRows, err := scanRows(rows)
		if err != nil {
			return document{}, err
		}
		doc.Tables[table] = tableRows
		doc.Counts[table] = len(tableRows)
	}
	return doc, nil
}

func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		row := map[string]any{}
		for i, column := range columns {
			row[column] = normalizeValue(values[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func normalizeValue(value any) any {
	switch v := value.(type) {
	case []byte:
		return string(v)
	default:
		return v
	}
}

func tableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	cols, err := tableColumnsInfoSchema(ctx, tx, table)
	if err == nil && len(cols) > 0 {
		return cols, nil
	}
	return tableColumnsPRAGMA(ctx, tx, table)
}

func tableColumnsInfoSchema(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name = ? ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func tableColumnsPRAGMA(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func insertRow(ctx context.Context, tx *sql.Tx, table string, columns []string, row map[string]any) error {
	var names []string
	var placeholders []string
	var args []any
	for _, column := range columns {
		value, ok := row[column]
		if !ok {
			continue
		}
		names = append(names, column)
		placeholders = append(placeholders, "?")
		args = append(args, value)
	}
	if len(names) == 0 {
		return nil
	}
	query := "INSERT INTO " + table + "(" + strings.Join(names, ",") + ") VALUES(" + strings.Join(placeholders, ",") + ")"
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func (s *Service) record(ctx context.Context, filename string, size int, status string) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO backups(id, filename, size_bytes, format, status) VALUES(?,?,?,?,?)`, id, filename, size, "opbackup", status)
	return err
}

func (s *Service) passphrase(password string) string {
	if strings.TrimSpace(password) != "" {
		return password
	}
	return s.appSecret
}

func (s *Service) decryptEnvelope(envelope encryptedDocument, password string) (string, error) {
	if envelope.KDF == "" {
		box := secure.NewBox(s.passphrase(password))
		return box.DecryptString(envelope.Ciphertext)
	}
	if envelope.KDF != BackupKDF {
		return "", errors.New("unsupported backup kdf")
	}
	if envelope.Iterations <= 0 || envelope.Salt == "" {
		return "", errors.New("invalid backup kdf parameters")
	}
	salt, err := base64.RawURLEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return "", err
	}
	key := pbkdf2Key([]byte(s.passphrase(password)), salt, envelope.Iterations, backupKeyBytes, sha256.New)
	return decryptWithKey(key, envelope.Ciphertext)
}

func encryptWithKey(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "v2:" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func decryptWithKey(key []byte, ciphertext string) (string, error) {
	encoded := strings.TrimPrefix(ciphertext, "v2:")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := raw[:gcm.NonceSize()]
	data := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func pbkdf2Key(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	hashLen := h().Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var output []byte
	for block := 1; block <= numBlocks; block++ {
		u := pbkdf2F(password, salt, iterations, block, h)
		output = append(output, u...)
	}
	return output[:keyLen]
}

func pbkdf2F(password, salt []byte, iterations, blockIndex int, h func() hash.Hash) []byte {
	mac := hmac.New(h, password)
	_, _ = mac.Write(salt)
	_, _ = mac.Write([]byte{
		byte(blockIndex >> 24),
		byte(blockIndex >> 16),
		byte(blockIndex >> 8),
		byte(blockIndex),
	})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		mac = hmac.New(h, password)
		_, _ = mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
