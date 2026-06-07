package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

const CookieName = "openpass_session"

type Service struct {
	db            *sql.DB
	adminPassword string
	sessionTTL    time.Duration
}

func New(database *sql.DB, adminPassword string) *Service {
	return &Service{
		db:            database,
		adminPassword: adminPassword,
		sessionTTL:    12 * time.Hour,
	}
}

func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/admin/login", s.Login)
	mux.Handle("POST /api/admin/logout", s.Require(http.HandlerFunc(s.Logout)))
	mux.Handle("GET /api/admin/me", s.Require(http.HandlerFunc(s.Me)))
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if !sameSecret(body.Password, s.adminPassword) {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	token, err := randomHex(32)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}
	id, err := randomHex(16)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
	}
	expires := time.Now().UTC().Add(s.sessionTTL)
	if _, err := s.db.Exec(
		`INSERT INTO admin_sessions(id, token_hash, expires_at) VALUES(?,?,?)`,
		id,
		secure.SHA256Hex(token),
		expires.Format(time.RFC3339),
	); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "session_error")
		return
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
