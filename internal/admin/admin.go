package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

const CookieName = "openpass_session"

type contextKey string

const userContextKey contextKey = "openpass_user"

// CurrentUser is the authenticated account attached to every request that
// passed Require. Handlers scope their queries by ID so one user can never
// read another user's vault.
type CurrentUser struct {
	ID                 string
	Email              string
	Role               string
	MustChangePassword bool
}

// IsAdmin reports whether the user may manage accounts (and only accounts:
// admin does not get access to other users' vault data).
func (u *CurrentUser) IsAdmin() bool {
	return u.Role == "admin"
}

func FromContext(ctx context.Context) (*CurrentUser, bool) {
	user, ok := ctx.Value(userContextKey).(*CurrentUser)
	return user, ok
}

func withContext(ctx context.Context, user *CurrentUser) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// userRecord is the full users row; the plain password is never stored.
type userRecord struct {
	ID                 string
	Email              string
	DisplayName        string
	PasswordHash       string
	RecoveryHash       string
	Role               string
	Status             string
	MustChangePassword bool
}

type Service struct {
	db  *sql.DB
	box secure.Box
	// configuredPassword is supplied at startup (env var or a generated
	// temporary one). It only bootstraps the first admin and feeds the CLI
	// reset; the database is the source of truth afterwards.
	configuredPassword string
	sessionTTL         time.Duration
}

func New(database *sql.DB, adminPassword string, secretKey ...string) *Service {
	sec := adminPassword
	if len(secretKey) > 0 && strings.TrimSpace(secretKey[0]) != "" {
		sec = secretKey[0]
	}
	return &Service{
		db:                 database,
		box:                secure.NewBox(sec),
		configuredPassword: adminPassword,
		sessionTTL:         12 * time.Hour,
	}
}

// Bootstrap creates the first admin account when the users table is empty, so
// a fresh install (or a database filled by cmd/migrate-sqlite) always has a
// way in. email comes from config (OPENPASS_ADMIN_EMAIL).
func (s *Service) Bootstrap(email string) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	email = NormalizeEmail(email)
	if email == "" {
		return errors.New("bootstrap admin email is empty")
	}
	_, err := s.createAccount(context.Background(), createAccountInput{
		Email:        email,
		DisplayName:  "Administrador",
		Password:     s.configuredPassword,
		Role:         "admin",
		MustChange:   false,
		WithRecovery: true,
	})
	return err
}

// ResetPassword overwrites the first admin's password with the one currently
// configured and drops only that admin's sessions. Used by
// OPENPASS_ADMIN_PASSWORD_RESET so an operator can regain access from the CLI
// without touching the database.
func (s *Service) ResetPassword() error {
	var id string
	err := s.db.QueryRow(`SELECT id FROM users WHERE role = 'admin' ORDER BY created_at ASC LIMIT 1`).Scan(&id)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	hash, err := secure.HashPassword(s.configuredPassword)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`UPDATE users SET password_hash = $1, must_change_password = 0, updated_at = $2 WHERE id = $3`,
		hash, now, id,
	); err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM sessions WHERE user_id = $1`, id)
	return err
}

func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/admin/login", s.Login)
	mux.Handle("POST /api/admin/logout", s.Require(http.HandlerFunc(s.Logout)))
	mux.Handle("GET /api/admin/me", s.Require(http.HandlerFunc(s.Me)))
	mux.Handle("POST /api/admin/change-password", s.Require(http.HandlerFunc(s.ChangePassword)))
	mux.Handle("GET /api/admin/recovery-key", s.Require(http.HandlerFunc(s.GetRecoveryKey)))
	mux.Handle("POST /api/admin/regenerate-recovery-key", s.Require(http.HandlerFunc(s.RegenerateRecoveryKey)))
	mux.HandleFunc("POST /api/admin/recover-password", s.RecoverPassword)
}

// NormalizeEmail is the canonical form stored in users.email: trimmed and
// lowercased, so "User@X" and "user@x" are the same account.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

type createAccountInput struct {
	Email        string
	DisplayName  string
	Password     string
	Role         string // "" -> user
	InvitedBy    string // "" -> none
	MustChange   bool
	WithRecovery bool
}

// createAccount is the single place accounts are created (bootstrap and the
// admin user-management handlers), so hashing, normalization and the
// created/updated timestamps stay consistent. It returns the new user ID.
func (s *Service) createAccount(ctx context.Context, input createAccountInput) (string, error) {
	email := NormalizeEmail(input.Email)
	if email == "" {
		return "", errors.New("email required")
	}
	if !strings.Contains(email, "@") {
		return "", errors.New("email inválido")
	}
	hash, err := secure.HashPassword(input.Password)
	if err != nil {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	role := input.Role
	if role == "" {
		role = "user"
	}
	mustChange := 0
	if input.MustChange {
		mustChange = 1
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var invitedBy any
	if input.InvitedBy != "" {
		invitedBy = input.InvitedBy
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO users(
		id, email, display_name, password_hash, role, status, must_change_password,
		invited_by, created_at, updated_at
	) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$8,$9)`,
		id, email, strings.TrimSpace(input.DisplayName), hash, role, mustChange,
		invitedBy, now, now,
	)
	if err != nil {
		if opdb.IsUniqueViolation(err) {
			return "", errors.New("já existe uma conta com este e-mail")
		}
		return "", err
	}
	if input.WithRecovery {
		if _, err := s.generateAndSaveRecoveryKey(ctx, id); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (s *Service) findUserByEmail(ctx context.Context, email string) (userRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT id, email, display_name, password_hash, recovery_key_hash, role, status, must_change_password
		FROM users WHERE email = $1`, NormalizeEmail(email)))
}

func (s *Service) getUser(ctx context.Context, id string) (userRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT id, email, display_name, password_hash, recovery_key_hash, role, status, must_change_password
		FROM users WHERE id = $1`, id))
}

func scanUser(row *sql.Row) (userRecord, error) {
	var u userRecord
	var displayName, recoveryHash sql.NullString
	var mustChange int
	if err := row.Scan(&u.ID, &u.Email, &displayName, &u.PasswordHash, &recoveryHash, &u.Role, &u.Status, &mustChange); err != nil {
		return userRecord{}, err
	}
	u.DisplayName = displayName.String
	u.RecoveryHash = recoveryHash.String
	u.MustChangePassword = mustChange == 1
	return u, nil
}

func (s *Service) generateAndSaveRecoveryKey(ctx context.Context, userID string) (string, error) {
	const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	key := fmt.Sprintf("OP-REC-%s-%s-%s-%s", b[0:4], b[4:8], b[8:12], b[12:16])
	enc, err := s.box.EncryptString(key)
	if err != nil {
		return "", err
	}
	normHash := secure.SHA256Hex(normalizeRecoveryKey(key))
	_, err = s.db.ExecContext(ctx, `UPDATE users SET recovery_key_enc = $1, recovery_key_hash = $2, updated_at = $3 WHERE id = $4`,
		enc, normHash, time.Now().UTC().Format(time.RFC3339), userID,
	)
	if err != nil {
		return "", err
	}
	return key, nil
}

// ensureRecoveryKey returns the user's current recovery key, generating one
// on first use (accounts restored from older imports may not have it yet).
func (s *Service) ensureRecoveryKey(ctx context.Context, userID string) (string, error) {
	var enc string
	err := s.db.QueryRowContext(ctx, `SELECT recovery_key_enc FROM users WHERE id = $1`, userID).Scan(&enc)
	if err == sql.ErrNoRows || (err == nil && enc == "") {
		return s.generateAndSaveRecoveryKey(ctx, userID)
	}
	if err != nil {
		return "", err
	}
	key, err := s.box.DecryptString(enc)
	if err != nil {
		return s.generateAndSaveRecoveryKey(ctx, userID)
	}
	return key, nil
}

// normalizeRecoveryKey reduces a recovery key to its 16-character body so the
// same key is accepted whether the user pastes it formatted
// (OP-REC-ABCD-EFGH-JKLM-NPQR), lowercased, or stripped of every separator.
// Separators are removed *before* the OP-REC prefix is stripped, otherwise an
// input without dashes would keep the prefix glued to the body and never match.
func normalizeRecoveryKey(key string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(key)) {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	// The body alphabet excludes "O", so trimming these prefixes can never eat
	// part of the body itself.
	k := strings.TrimPrefix(b.String(), "OPREC")
	k = strings.TrimPrefix(k, "OP")
	return k
}

func (s *Service) createSession(w http.ResponseWriter, userID string) error {
	token, err := randomHex(32)
	if err != nil {
		return err
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	expires := now.Add(s.sessionTTL)
	if _, err := s.db.Exec(
		`INSERT INTO sessions(id, user_id, token_hash, created_at, expires_at) VALUES($1,$2,$3,$4,$5)`,
		id,
		userID,
		secure.SHA256Hex(token),
		now.Format(time.RFC3339),
		expires.Format(time.RFC3339),
	); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
		Expires:  expires,
	})
	return nil
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	user, err := s.findUserByEmail(r.Context(), body.Email)
	if err != nil || user.Status != "active" {
		// Same response for unknown e-mail and wrong password.
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	ok, needsRehash := secure.VerifyPassword(body.Password, user.PasswordHash)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if needsRehash {
		// Password was stored in the legacy single-admin SHA-256 format;
		// upgrade it now while we know the plaintext.
		if hash, hashErr := secure.HashPassword(body.Password); hashErr == nil {
			_, _ = s.db.ExecContext(r.Context(),
				`UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`,
				hash, time.Now().UTC().Format(time.RFC3339), user.ID,
			)
		}
	}

	if err := s.createSession(w, user.ID); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"authenticated":        true,
		"email":                user.Email,
		"role":                 user.Role,
		"must_change_password": user.MustChangePassword,
	})
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash = $1`, secure.SHA256Hex(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	httpjson.Write(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"authenticated":        true,
		"email":                user.Email,
		"role":                 user.Role,
		"must_change_password": user.MustChangePassword,
	})
}

func (s *Service) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	ctx := r.Context()
	current, ok := FromContext(ctx)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, err := s.getUser(ctx, current.ID)
	if err != nil {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if ok, _ := secure.VerifyPassword(body.CurrentPassword, user.PasswordHash); !ok {
		httpjson.Error(w, http.StatusBadRequest, "senha_atual_incorreta")
		return
	}
	if err := s.setNewPassword(ctx, user.ID, body.NewPassword); err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) GetRecoveryKey(w http.ResponseWriter, r *http.Request) {
	current, ok := FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	key, err := s.ensureRecoveryKey(r.Context(), current.ID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "recovery_key_error")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"recovery_key": key})
}

func (s *Service) RegenerateRecoveryKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	ctx := r.Context()
	current, ok := FromContext(ctx)
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, err := s.getUser(ctx, current.ID)
	if err != nil {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if ok, _ := secure.VerifyPassword(body.Password, user.PasswordHash); !ok {
		httpjson.Error(w, http.StatusUnauthorized, "senha_incorreta")
		return
	}
	key, err := s.generateAndSaveRecoveryKey(ctx, user.ID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "error_generating_recovery_key")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"recovery_key": key})
}

// RecoverPassword lets an account owner reset their password from the login
// screen with their recovery key. The e-mail is required now that there is
// more than one account: it selects which user the key must match.
func (s *Service) RecoverPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		RecoveryKey string `json:"recovery_key"`
		NewPassword string `json:"new_password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	ctx := r.Context()
	user, err := s.findUserByEmail(ctx, body.Email)
	if err != nil || user.Status != "active" || user.RecoveryHash == "" {
		httpjson.Error(w, http.StatusBadRequest, "chave_de_recuperacao_invalida")
		return
	}
	inputNorm := normalizeRecoveryKey(body.RecoveryKey)
	if inputNorm == "" || !secure.VerifySHA256(inputNorm, user.RecoveryHash) {
		httpjson.Error(w, http.StatusUnauthorized, "chave_de_recuperacao_invalida")
		return
	}

	if err := s.setNewPassword(ctx, user.ID, body.NewPassword); err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	newKey, err := s.generateAndSaveRecoveryKey(ctx, user.ID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "error_rotating_recovery_key")
		return
	}

	// Every existing session of this account is dropped: a recovery means the
	// old password may be compromised.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, user.ID)

	if err := s.createSession(w, user.ID); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}

	httpjson.Write(w, http.StatusOK, map[string]any{
		"recovered":        true,
		"new_recovery_key": newKey,
	})
}

func (s *Service) setNewPassword(ctx context.Context, userID, newPassword string) error {
	newPassword = strings.TrimSpace(newPassword)
	if len(newPassword) < 6 {
		return errors.New("a nova senha deve ter pelo menos 6 caracteres")
	}
	hash, err := secure.HashPassword(newPassword)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = $1, must_change_password = 0, updated_at = $2 WHERE id = $3`,
		hash, time.Now().UTC().Format(time.RFC3339), userID,
	)
	return err
}

// Require resolves the session cookie into a CurrentUser and rejects anything
// else: missing/expired session, unknown user, or a disabled account.
func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		tokenHash := secure.SHA256Hex(cookie.Value)

		var sessionID, expiresRaw string
		var user CurrentUser
		var status string
		var mustChange int
		err = s.db.QueryRow(
			`SELECT s.id, s.expires_at, u.id, u.email, u.role, u.status, u.must_change_password
			 FROM sessions s JOIN users u ON u.id = s.user_id
			 WHERE s.token_hash = $1`, tokenHash,
		).Scan(&sessionID, &expiresRaw, &user.ID, &user.Email, &user.Role, &status, &mustChange)
		if err != nil {
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		expires, err := time.Parse(time.RFC3339, expiresRaw)
		if err != nil || time.Now().UTC().After(expires) {
			_, _ = s.db.Exec(`DELETE FROM sessions WHERE id = $1`, sessionID)
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if status != "active" {
			_, _ = s.db.Exec(`DELETE FROM sessions WHERE id = $1`, sessionID)
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		user.MustChangePassword = mustChange == 1

		next.ServeHTTP(w, r.WithContext(withContext(r.Context(), &user)))
	})
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// randomID matches the 32-char hex IDs used by every other table.
func randomID() (string, error) {
	return randomHex(16)
}
