package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/httpjson"
)

type Service struct {
	db *sql.DB
}

type Entry struct {
	ID         string  `json:"id"`
	APIKeyID   *string `json:"api_key_id,omitempty"`
	OwnerID    *string `json:"owner_id,omitempty"`
	KeyPrefix  string  `json:"key_prefix,omitempty"`
	IPAddress  string  `json:"ip_address,omitempty"`
	UserAgent  string  `json:"user_agent,omitempty"`
	Method     string  `json:"method"`
	Endpoint   string  `json:"endpoint"`
	RequestID  string  `json:"request_id"`
	StatusCode int     `json:"status_code"`
	DurationMS int     `json:"duration_ms"`
	Result     string  `json:"result"`
	ErrorMsg   string  `json:"error_msg,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

type Filter struct {
	OwnerID   string
	APIKeyID  string
	KeyPrefix string
	Result    string
	Endpoint  string
	IPAddress string
	Limit     int
}

func New(database *sql.DB) *Service {
	return &Service{db: database}
}

func (s *Service) RegisterAdminRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/audit-logs", require(http.HandlerFunc(s.ListHandler)))
}

func (s *Service) ListHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := admin.FromContext(r.Context())
	if !ok {
		httpjson.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	// owner-scoped: users only ever see audit rows for their own API keys.
	logs, err := s.List(r.Context(), Filter{
		OwnerID:   user.ID,
		APIKeyID:  r.URL.Query().Get("api_key_id"),
		KeyPrefix: r.URL.Query().Get("key_prefix"),
		Result:    r.URL.Query().Get("result"),
		Endpoint:  r.URL.Query().Get("endpoint"),
		IPAddress: r.URL.Query().Get("ip_address"),
		Limit:     limit,
	})
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_audit_logs_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": logs})
}

func (s *Service) Record(ctx context.Context, entry Entry) error {
	if entry.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		entry.ID = id
	}
	if entry.RequestID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		entry.RequestID = id
	}
	if entry.Result == "" {
		entry.Result = "success"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_audit_logs(
		id, api_key_id, owner_id, key_prefix, ip_address, user_agent, method, endpoint,
		request_id, status_code, duration_ms, result, error_msg, created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		entry.ID,
		entry.APIKeyID,
		entry.OwnerID,
		entry.KeyPrefix,
		entry.IPAddress,
		entry.UserAgent,
		entry.Method,
		entry.Endpoint,
		entry.RequestID,
		entry.StatusCode,
		entry.DurationMS,
		entry.Result,
		emptyToNil(entry.ErrorMsg),
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Service) List(ctx context.Context, filter Filter) ([]Entry, error) {
	query := `SELECT id, api_key_id, key_prefix, ip_address, user_agent, method, endpoint, request_id, status_code, duration_ms, result, error_msg, created_at FROM api_audit_logs`
	var where []string
	var args []any
	// placeholder tracks PostgreSQL's $n positions as conditions are appended.
	placeholder := 0
	addFilter := func(column, value string) {
		placeholder++
		where = append(where, fmt.Sprintf("%s = $%d", column, placeholder))
		args = append(args, value)
	}
	if filter.OwnerID != "" {
		addFilter("owner_id", filter.OwnerID)
	}
	if filter.APIKeyID != "" {
		addFilter("api_key_id", filter.APIKeyID)
	}
	if filter.KeyPrefix != "" {
		addFilter("key_prefix", filter.KeyPrefix)
	}
	if filter.Result != "" {
		addFilter("result", filter.Result)
	}
	if filter.Endpoint != "" {
		addFilter("endpoint", filter.Endpoint)
	}
	if filter.IPAddress != "" {
		addFilter("ip_address", filter.IPAddress)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC"
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	placeholder++
	query += fmt.Sprintf(" LIMIT $%d", placeholder)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var entry Entry
		var apiKeyID, keyPrefix, ip, ua, errMsg sql.NullString
		if err := rows.Scan(&entry.ID, &apiKeyID, &keyPrefix, &ip, &ua, &entry.Method, &entry.Endpoint, &entry.RequestID, &entry.StatusCode, &entry.DurationMS, &entry.Result, &errMsg, &entry.CreatedAt); err != nil {
			return nil, err
		}
		if apiKeyID.Valid {
			entry.APIKeyID = &apiKeyID.String
		}
		entry.KeyPrefix = keyPrefix.String
		entry.IPAddress = ip.String
		entry.UserAgent = ua.String
		entry.ErrorMsg = errMsg.String
		out = append(out, entry)
	}
	return out, rows.Err()
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func emptyToNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}
