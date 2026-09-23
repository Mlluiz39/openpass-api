package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

const CookieName = "openpass_session"

type Service struct {
	db *sql.DB
	box secure.Box
	// configuredPassword is the password supplied at startup (env var or a
	// generated temporary one). It stays immutable for the lifetime of the
	// process: the database is the source of truth for the *current* password,
	// and configuredPassword is only the fallback used to bootstrap and to
	// restore access via ResetPassword.
	configuredPassword string
	sessionTTL         time.Duration
}

func New(database *sql.DB, adminPassword string, secretKey ...string) *Service {
	sec := adminPassword
	if len(secretKey) > 0 && strings.TrimSpace(secretKey[0]) != "" {
		sec = secretKey[0]
	}
	s := &Service{
		db:                 database,
		box:                secure.NewBox(sec),
		configuredPassword: adminPassword,
		sessionTTL:         12 * time.Hour,
	}
	_ = s.ensureSettings()
	return s
}

// ResetPassword overwrites the stored admin password with the one currently
// configured, discarding any password previously set through the panel. It is
// used by OPENPASS_ADMIN_PASSWORD_RESET so an operator can always regain access
// from the CLI without editing the database by hand.
func (s *Service) ResetPassword() error {
	if err := s.setNewPassword(s.configuredPassword); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM admin_sessions`)
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

func (s *Service) ensureSettings() error {
	var hash string
	err := s.db.QueryRow(`SELECT value FROM app_settings WHERE key = 'admin_password_hash'`).Scan(&hash)
	if err == sql.ErrNoRows {
		salt, err := randomHex(16)
		if err != nil {
			return err
		}
		passHash := secure.SHA256Hex(salt + ":" + s.configuredPassword)
		_, err = s.db.Exec(`INSERT OR REPLACE INTO app_settings(key, value) VALUES('admin_password_salt', ?), ('admin_password_hash', ?)`, salt, passHash)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	var recEnc string
	err = s.db.QueryRow(`SELECT value FROM app_settings WHERE key = 'recovery_key_enc'`).Scan(&recEnc)
	if err == sql.ErrNoRows {
		_, err = s.generateAndSaveRecoveryKey()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (s *Service) generateAndSaveRecoveryKey() (string, error) {
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
	_, err = s.db.Exec(`INSERT OR REPLACE INTO app_settings(key, value) VALUES('recovery_key_enc', ?), ('recovery_key_hash', ?)`, enc, normHash)
	if err != nil {
		return "", err
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

func (s *Service) verifyPassword(password string) bool {
	_ = s.ensureSettings()
	var salt, hash string
	err := s.db.QueryRow(`SELECT value FROM app_settings WHERE key = 'admin_password_salt'`).Scan(&salt)
	if err == nil {
		err = s.db.QueryRow(`SELECT value FROM app_settings WHERE key = 'admin_password_hash'`).Scan(&hash)
		if err == nil && salt != "" && hash != "" {
			return secure.VerifySHA256(salt+":"+password, hash)
		}
	}
	return sameSecret(password, s.configuredPassword)
}

func (s *Service) setNewPassword(newPassword string) error {
	newPassword = strings.TrimSpace(newPassword)
	if len(newPassword) < 6 {
		return errors.New("a nova senha deve ter pelo menos 6 caracteres")
	}
	salt, err := randomHex(16)
	if err != nil {
		return err
	}
	passHash := secure.SHA256Hex(salt + ":" + newPassword)
	_, err = s.db.Exec(`INSERT OR REPLACE INTO app_settings(key, value) VALUES('admin_password_salt', ?), ('admin_password_hash', ?)`, salt, passHash)
	if err != nil {
		return err
	}
	return nil
}

func (s *Service) createSession(w http.ResponseWriter) error {
	token, err := randomHex(32)
	if err != nil {
		return err
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	expires := time.Now().UTC().Add(s.sessionTTL)
	if _, err := s.db.Exec(
		`INSERT INTO admin_sessions(id, token_hash, expires_at) VALUES(?,?,?)`,
		id,
		secure.SHA256Hex(token),
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
		Password string `json:"password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if !s.verifyPassword(body.Password) {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := s.createSession(w); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		_, _ = s.db.Exec(`DELETE FROM admin_sessions WHERE token_hash = ?`, secure.SHA256Hex(cookie.Value))
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
	httpjson.Write(w, http.StatusOK, map[string]any{"authenticated": true})
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
	if !s.verifyPassword(body.CurrentPassword) {
		httpjson.Error(w, http.StatusBadRequest, "senha_atual_incorreta")
		return
	}
	if err := s.setNewPassword(body.NewPassword); err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Service) GetRecoveryKey(w http.ResponseWriter, r *http.Request) {
	_ = s.ensureSettings()
	var enc string
	err := s.db.QueryRowContext(r.Context(), `SELECT value FROM app_settings WHERE key = 'recovery_key_enc'`).Scan(&enc)
	if err != nil {
		key, err := s.generateAndSaveRecoveryKey()
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "recovery_key_error")
			return
		}
		httpjson.Write(w, http.StatusOK, map[string]string{"recovery_key": key})
		return
	}
	key, err := s.box.DecryptString(enc)
	if err != nil {
		key, err = s.generateAndSaveRecoveryKey()
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "recovery_key_error")
			return
		}
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
	if !s.verifyPassword(body.Password) {
		httpjson.Error(w, http.StatusUnauthorized, "senha_incorreta")
		return
	}
	key, err := s.generateAndSaveRecoveryKey()
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "error_generating_recovery_key")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"recovery_key": key})
}

func (s *Service) RecoverPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RecoveryKey string `json:"recovery_key"`
		NewPassword string `json:"new_password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	_ = s.ensureSettings()
	var storedHash string
	err := s.db.QueryRowContext(r.Context(), `SELECT value FROM app_settings WHERE key = 'recovery_key_hash'`).Scan(&storedHash)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "chave_de_recuperacao_invalida")
		return
	}
	inputNorm := normalizeRecoveryKey(body.RecoveryKey)
	if inputNorm == "" || !secure.VerifySHA256(inputNorm, storedHash) {
		httpjson.Error(w, http.StatusUnauthorized, "chave_de_recuperacao_invalida")
		return
	}

	if err := s.setNewPassword(body.NewPassword); err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	newKey, err := s.generateAndSaveRecoveryKey()
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "error_rotating_recovery_key")
		return
	}

	_, _ = s.db.ExecContext(r.Context(), `DELETE FROM admin_sessions`)

	if err := s.createSession(w); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}

	httpjson.Write(w, http.StatusOK, map[string]any{
		"recovered":        true,
		"new_recovery_key": newKey,
	})
}

func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var id string
		var expiresRaw string
		err = s.db.QueryRow(
			`SELECT id, expires_at FROM admin_sessions WHERE token_hash = ?`,
			secure.SHA256Hex(cookie.Value),
		).Scan(&id, &expiresRaw)
		if err != nil {
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		expires, err := time.Parse(time.RFC3339, expiresRaw)
		if err != nil || time.Now().UTC().After(expires) {
			_, _ = s.db.Exec(`DELETE FROM admin_sessions WHERE id = ?`, id)
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func sameSecret(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
