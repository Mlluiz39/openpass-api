package apikeys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openpass/api/internal/audit"
	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

var (
	ErrUnauthorized      = errors.New("unauthorized")
	ErrForbidden         = errors.New("forbidden")
	ErrRateLimitExceeded = errors.New("rate_limit_exceeded")
)

type contextKey string

const authContextKey contextKey = "openpass_api_key"

type Service struct {
	db       *sql.DB
	box      secure.Box
	limiter  *Limiter
	auditSvc *audit.Service
}

type CreateInput struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Env          string          `json:"env"`
	Permissions  map[string]bool `json:"permissions"`
	AllowedIPs   []string        `json:"allowed_ips"`
	VaultScope   []string        `json:"vault_scope"`
	RateLimitRPM int             `json:"rate_limit_rpm"`
	ExpiresAt    *string         `json:"expires_at"`
}

type CreatedKey struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	Token        string          `json:"token"`
	KeyPrefix    string          `json:"key_prefix"`
	KeySuffix    string          `json:"key_suffix"`
	Permissions  map[string]bool `json:"permissions"`
	AllowedIPs   []string        `json:"allowed_ips,omitempty"`
	VaultScope   []string        `json:"vault_scope,omitempty"`
	RateLimitRPM int             `json:"rate_limit_rpm"`
	IsActive     bool            `json:"is_active"`
	CreatedAt    string          `json:"created_at,omitempty"`
}

type KeyRecord struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	KeyPrefix    string          `json:"key_prefix"`
	KeySuffix    string          `json:"key_suffix"`
	Permissions  map[string]bool `json:"permissions"`
	AllowedIPs   []string        `json:"allowed_ips,omitempty"`
	VaultScope   []string        `json:"vault_scope,omitempty"`
	RateLimitRPM int             `json:"rate_limit_rpm"`
	IsActive     bool            `json:"is_active"`
	LastUsedAt   *string         `json:"last_used_at,omitempty"`
	ExpiresAt    *string         `json:"expires_at,omitempty"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

type AuthenticatedKey struct {
	ID           string
	Name         string
	Prefix       string
	Permissions  map[string]bool
	VaultScope   []string
	RateLimitRPM int
}

func New(database *sql.DB, secret string) *Service {
	return &Service{
		db:      database,
		box:     secure.NewBox(secret),
		limiter: NewLimiter(time.Minute),
	}
}

func (s *Service) SetAudit(service *audit.Service) {
	s.auditSvc = service
}

func FromContext(ctx context.Context) (*AuthenticatedKey, bool) {
	key, ok := ctx.Value(authContextKey).(*AuthenticatedKey)
	return key, ok
}

func WithContext(ctx context.Context, key *AuthenticatedKey) context.Context {
	return context.WithValue(ctx, authContextKey, key)
}

func (s *Service) Create(ctx context.Context, input CreateInput) (CreatedKey, error) {
	if strings.TrimSpace(input.Name) == "" {
		return CreatedKey{}, errors.New("name required")
	}
	env := input.Env
	if env == "" {
		env = "live"
	}
	generated, err := secure.GenerateAPIKey(env)
	if err != nil {
		return CreatedKey{}, err
	}
	id, err := randomID()
	if err != nil {
		return CreatedKey{}, err
	}
	encryptedToken, err := s.box.EncryptString(generated.Plaintext)
	if err != nil {
		return CreatedKey{}, err
	}
	if input.Permissions == nil {
		input.Permissions = map[string]bool{}
	}
	if input.RateLimitRPM <= 0 {
		input.RateLimitRPM = 60
	}
	permissionsJSON, err := marshalJSON(input.Permissions)
	if err != nil {
		return CreatedKey{}, err
	}
	allowedIPsJSON, err := marshalOptionalList(input.AllowedIPs)
	if err != nil {
		return CreatedKey{}, err
	}
	vaultScopeJSON, err := marshalOptionalList(input.VaultScope)
	if err != nil {
		return CreatedKey{}, err
	}

	_, err = s.db.ExecContext(ctx, `INSERT INTO api_keys(
		id, name, description, key_prefix, key_hash, key_suffix, encrypted_token,
		permissions, allowed_ips, vault_scope, rate_limit_rpm, expires_at
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		id,
		strings.TrimSpace(input.Name),
		strings.TrimSpace(input.Description),
		generated.Prefix,
		generated.Hash,
		generated.Suffix,
		encryptedToken,
		permissionsJSON,
		allowedIPsJSON,
		vaultScopeJSON,
		input.RateLimitRPM,
		input.ExpiresAt,
	)
	if err != nil {
		return CreatedKey{}, err
	}

	return CreatedKey{
		ID:           id,
		Name:         strings.TrimSpace(input.Name),
		Description:  strings.TrimSpace(input.Description),
		Token:        generated.Plaintext,
		KeyPrefix:    generated.Prefix,
		KeySuffix:    generated.Suffix,
		Permissions:  input.Permissions,
		AllowedIPs:   input.AllowedIPs,
		VaultScope:   input.VaultScope,
		RateLimitRPM: input.RateLimitRPM,
		IsActive:     true,
	}, nil
}

func (s *Service) Reveal(ctx context.Context, id string) (string, error) {
	var encrypted string
	if err := s.db.QueryRowContext(ctx, `SELECT encrypted_token FROM api_keys WHERE id = ?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	return s.box.DecryptString(encrypted)
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Service) List(ctx context.Context) ([]KeyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, key_prefix, key_suffix, permissions, allowed_ips, vault_scope, rate_limit_rpm, is_active, last_used_at, expires_at, created_at, updated_at FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyRecord
	for rows.Next() {
		var record KeyRecord
		var description, allowedRaw, scopeRaw, lastUsed, expires sql.NullString
		var permissionsRaw string
		var isActive int
		if err := rows.Scan(&record.ID, &record.Name, &description, &record.KeyPrefix, &record.KeySuffix, &permissionsRaw, &allowedRaw, &scopeRaw, &record.RateLimitRPM, &isActive, &lastUsed, &expires, &record.CreatedAt, &record.UpdatedAt); err != nil {
			return nil, err
		}
		record.Description = description.String
		record.Permissions = unmarshalPermissions(permissionsRaw)
		record.AllowedIPs = unmarshalList(allowedRaw.String)
		record.VaultScope = unmarshalList(scopeRaw.String)
		record.IsActive = isActive == 1
		if lastUsed.Valid {
			record.LastUsedAt = &lastUsed.String
		}
		if expires.Valid {
			record.ExpiresAt = &expires.String
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *Service) Authenticate(r *http.Request, requiredPermission string) (*AuthenticatedKey, int, error) {
	token := extractBearer(r)
	if token == "" {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}
	prefix := secure.ExtractPrefix(token)
	if prefix == "" {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}

	rows, err := s.db.QueryContext(r.Context(), `SELECT id, name, key_hash, permissions, allowed_ips, vault_scope, rate_limit_rpm, expires_at FROM api_keys WHERE key_prefix = ? AND is_active = 1`, prefix)
	if err != nil {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}
	defer rows.Close()

	for rows.Next() {
		key, status, err := s.scanAndCheckCandidate(r, rows, token, requiredPermission)
		if err == nil {
			_, _ = s.db.ExecContext(r.Context(), `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), key.ID)
			return key, http.StatusOK, nil
		}
		if status == http.StatusForbidden || status == http.StatusTooManyRequests {
			return nil, status, err
		}
	}
	return nil, http.StatusUnauthorized, ErrUnauthorized
}

func (s *Service) RequirePermission(requiredPermission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		key, status, err := s.Authenticate(r, requiredPermission)
		if err != nil {
			if status == http.StatusForbidden {
				httpjson.Write(w, status, map[string]any{"error": "forbidden", "required_permission": requiredPermission})
				s.recordAudit(r, key, status, "denied", "forbidden", time.Since(start))
				return
			}
			if status == http.StatusTooManyRequests {
				writeRateLimit(w, key)
				s.recordAudit(r, key, status, "denied", "rate_limit_exceeded", time.Since(start))
				return
			}
			httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
			s.recordAudit(r, key, status, "denied", "unauthorized", time.Since(start))
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r.WithContext(WithContext(r.Context(), key)))
		result := "success"
		if recorder.status >= 500 {
			result = "error"
		} else if recorder.status >= 400 {
			result = "denied"
		}
		s.recordAudit(r, key, recorder.status, result, "", time.Since(start))
	})
}

func (s *Service) RegisterAdminRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/keys", require(http.HandlerFunc(s.ListHandler)))
	mux.Handle("POST /api/admin/keys", require(http.HandlerFunc(s.CreateHandler)))
	mux.Handle("GET /api/admin/keys/{id}/reveal", require(http.HandlerFunc(s.RevealHandler)))
	mux.Handle("PATCH /api/admin/keys/{id}/revoke", require(http.HandlerFunc(s.RevokeHandler)))
	mux.Handle("DELETE /api/admin/keys/{id}", require(http.HandlerFunc(s.DeleteHandler)))
}

func (s *Service) RegisterAPIRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/auth/me", s.RequirePermission("", http.HandlerFunc(s.AuthMeHandler)))
}

func (s *Service) AuthMeHandler(w http.ResponseWriter, r *http.Request) {
	key, ok := FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"id":             key.ID,
		"name":           key.Name,
		"key_prefix":     key.Prefix,
		"permissions":    key.Permissions,
		"vault_scope":    key.VaultScope,
		"rate_limit_rpm": key.RateLimitRPM,
	})
}

func (s *Service) ListHandler(w http.ResponseWriter, r *http.Request) {
	keys, err := s.List(r.Context())
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_keys_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": keys})
}

func (s *Service) CreateHandler(w http.ResponseWriter, r *http.Request) {
	var input CreateInput
	if err := httpjson.Decode(r, &input); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	created, err := s.Create(r.Context(), input)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpjson.Write(w, http.StatusCreated, created)
}

func (s *Service) RevealHandler(w http.ResponseWriter, r *http.Request) {
	token, err := s.Reveal(r.Context(), r.PathValue("id"))
	if err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]string{"token": token})
}

func (s *Service) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.Revoke(r.Context(), r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (s *Service) DeleteHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.Delete(r.Context(), r.PathValue("id")); err != nil {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) scanAndCheckCandidate(r *http.Request, rows *sql.Rows, token, requiredPermission string) (*AuthenticatedKey, int, error) {
	var id, name, hash, permissionsRaw string
	var allowedRaw, scopeRaw, expiresRaw sql.NullString
	var rpm int
	if err := rows.Scan(&id, &name, &hash, &permissionsRaw, &allowedRaw, &scopeRaw, &rpm, &expiresRaw); err != nil {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}
	if !secure.VerifySHA256(token, hash) {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}
	if expiresRaw.Valid {
		expires, err := time.Parse(time.RFC3339, expiresRaw.String)
		if err == nil && time.Now().UTC().After(expires) {
			return nil, http.StatusUnauthorized, ErrUnauthorized
		}
	}
	if !ipAllowed(clientIP(r), unmarshalList(allowedRaw.String)) {
		return nil, http.StatusUnauthorized, ErrUnauthorized
	}
	permissions := unmarshalPermissions(permissionsRaw)
	if requiredPermission != "" && !permissions[requiredPermission] {
		return nil, http.StatusForbidden, ErrForbidden
	}
	if rpm <= 0 {
		rpm = 60
	}
	if !s.limiter.Allow(id, rpm) {
		return nil, http.StatusTooManyRequests, ErrRateLimitExceeded
	}
	return &AuthenticatedKey{
		ID:           id,
		Name:         name,
		Prefix:       secure.ExtractPrefix(token),
		Permissions:  permissions,
		VaultScope:   unmarshalList(scopeRaw.String),
		RateLimitRPM: rpm,
	}, http.StatusOK, nil
}

func (k *AuthenticatedKey) HasPermission(permission string) bool {
	if permission == "" {
		return true
	}
	return k.Permissions[permission]
}

func (k *AuthenticatedKey) CanAccessVault(vaultID string) bool {
	if len(k.VaultScope) == 0 {
		return true
	}
	for _, allowed := range k.VaultScope {
		if allowed == vaultID {
			return true
		}
	}
	return false
}

type Limiter struct {
	mu     sync.Mutex
	window time.Duration
	hits   map[string][]time.Time
}

func NewLimiter(window time.Duration) *Limiter {
	return &Limiter{window: window, hits: map[string][]time.Time{}}
}

func (l *Limiter) Allow(key string, limit int) bool {
	if limit <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	current := l.hits[key]
	kept := current[:0]
	for _, hit := range current {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= limit {
		l.hits[key] = kept
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

func extractBearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func ipAllowed(ip string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err == nil && network.Contains(parsedIP) {
				return true
			}
			continue
		}
		if net.ParseIP(entry).Equal(parsedIP) {
			return true
		}
	}
	return false
}

func writeRateLimit(w http.ResponseWriter, key *AuthenticatedKey) {
	limit := 60
	if key != nil && key.RateLimitRPM > 0 {
		limit = key.RateLimitRPM
	}
	reset := time.Now().Add(time.Minute).Unix()
	w.Header().Set("Retry-After", "60")
	w.Header().Set("X-RateLimit-Limit", stringInt(limit))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", stringInt64(reset))
	httpjson.Error(w, http.StatusTooManyRequests, "rate_limit_exceeded")
}

func marshalJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func marshalOptionalList(values []string) (*string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	raw, err := marshalJSON(values)
	if err != nil {
		return nil, err
	}
	return &raw, nil
}

func unmarshalPermissions(raw string) map[string]bool {
	out := map[string]bool{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
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

func stringInt(value int) string {
	return stringInt64(int64(value))
}

func stringInt64(value int64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	negative := value < 0
	if negative {
		value = -value
	}
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Service) recordAudit(r *http.Request, key *AuthenticatedKey, status int, result, message string, duration time.Duration) {
	if s.auditSvc == nil {
		return
	}
	var apiKeyID *string
	keyPrefix := secure.ExtractPrefix(extractBearer(r))
	if key != nil {
		id := key.ID
		apiKeyID = &id
		keyPrefix = key.Prefix
	}
	_ = s.auditSvc.Record(r.Context(), audit.Entry{
		APIKeyID:   apiKeyID,
		KeyPrefix:  keyPrefix,
		IPAddress:  clientIP(r),
		UserAgent:  r.UserAgent(),
		Method:     r.Method,
		Endpoint:   r.URL.Path,
		StatusCode: status,
		DurationMS: int(duration.Milliseconds()),
		Result:     result,
		ErrorMsg:   message,
	})
}
