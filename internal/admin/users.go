package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/httpjson"
	"github.com/openpass/api/internal/secure"
)

// UserView is the account shape returned by the user-management endpoints.
// It never exposes password or recovery material.
type UserView struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	DisplayName        string `json:"display_name,omitempty"`
	Role               string `json:"role"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
	CreatedAt          string `json:"created_at"`
}

// RegisterUserRoutes exposes account management. Every route is wrapped in
// adminOnly: regular users cannot list or touch accounts, and even admins
// only manage identity here — vault data stays scoped to its owner.
func (s *Service) RegisterUserRoutes(mux *http.ServeMux, require func(http.Handler) http.Handler) {
	mux.Handle("GET /api/admin/users", require(s.adminOnly(http.HandlerFunc(s.ListUsers))))
	mux.Handle("POST /api/admin/users", require(s.adminOnly(http.HandlerFunc(s.CreateUser))))
	mux.Handle("PATCH /api/admin/users/{id}", require(s.adminOnly(http.HandlerFunc(s.UpdateUser))))
	mux.Handle("DELETE /api/admin/users/{id}", require(s.adminOnly(http.HandlerFunc(s.DeleteUser))))
}

func (s *Service) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := FromContext(r.Context())
		if !ok || !user.IsAdmin() {
			httpjson.Error(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT id, email, display_name, role, status, must_change_password, created_at
		FROM users ORDER BY created_at ASC`)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_users_failed")
		return
	}
	defer rows.Close()
	out := []UserView{}
	for rows.Next() {
		view, err := scanUserView(rows)
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "list_users_failed")
			return
		}
		out = append(out, view)
	}
	if err := rows.Err(); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "list_users_failed")
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"data": out})
}

// CreateUser invites a new account with a temporary password. The plaintext
// password is returned exactly once; the user is forced to change it at first
// login.
func (s *Service) CreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	role := body.Role
	if role == "" {
		role = "user"
	}
	if role != "admin" && role != "user" {
		httpjson.Error(w, http.StatusBadRequest, "papel_inválido")
		return
	}

	temporary := ""
	password := strings.TrimSpace(body.Password)
	if password == "" {
		generated, err := randomHex(8)
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "password_generation_failed")
			return
		}
		password = generated
		temporary = generated
	}
	if len(password) < 6 {
		httpjson.Error(w, http.StatusBadRequest, "a senha deve ter pelo menos 6 caracteres")
		return
	}

	current, _ := FromContext(r.Context())
	userID, err := s.createAccount(r.Context(), createAccountInput{
		Email:        body.Email,
		DisplayName:  body.DisplayName,
		Password:     password,
		Role:         role,
		InvitedBy:    current.ID,
		MustChange:   true,
		WithRecovery: true,
	})
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	view, err := s.getUserView(r.Context(), userID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_created_but_unreadable")
		return
	}
	response := map[string]any{"user": view}
	if temporary != "" {
		response["temporary_password"] = temporary
	}
	httpjson.Write(w, http.StatusCreated, response)
}

// UpdateUser edits profile, role, status or resets the password. Self-lockout
// is rejected: you cannot change your own role/status, remove the last admin,
// or delete yourself.
func (s *Service) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName   *string `json:"display_name"`
		Role          *string `json:"role"`
		Status        *string `json:"status"`
		ResetPassword bool    `json:"reset_password"`
	}
	if err := httpjson.Decode(r, &body); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "invalid_json")
		return
	}
	ctx := r.Context()
	targetID := r.PathValue("id")
	current, _ := FromContext(ctx)
	target, err := s.getUser(ctx, targetID)
	if err == sql.ErrNoRows {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_lookup_failed")
		return
	}

	if target.ID == current.ID {
		if body.Role != nil && *body.Role != target.Role {
			httpjson.Error(w, http.StatusBadRequest, "não_altera_proprio_papel")
			return
		}
		if body.Status != nil && *body.Status != target.Status {
			httpjson.Error(w, http.StatusBadRequest, "não_altera_proprio_status")
			return
		}
		if body.ResetPassword {
			// Resetting yourself here would kill your own session mid-request;
			// use Segurança → Alterar Senha instead.
			httpjson.Error(w, http.StatusBadRequest, "use_a_tela_de_segurança_para_mudar_a_propria_senha")
			return
		}
	}
	if body.Role != nil && target.Role == "admin" && *body.Role != "admin" {
		if err := s.ensureAnotherAdminExists(ctx, target.ID); err != nil {
			httpjson.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if body.Role != nil && *body.Role != "admin" && *body.Role != "user" {
		httpjson.Error(w, http.StatusBadRequest, "papel_inválido")
		return
	}
	if body.Status != nil && *body.Status != "active" && *body.Status != "disabled" {
		httpjson.Error(w, http.StatusBadRequest, "status_inválido")
		return
	}

	var sets []string
	var args []any
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if body.DisplayName != nil {
		add("display_name", strings.TrimSpace(*body.DisplayName))
	}
	if body.Role != nil {
		add("role", *body.Role)
	}
	if body.Status != nil {
		add("status", *body.Status)
	}

	temporary := ""
	if body.ResetPassword {
		generated, err := randomHex(8)
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "password_generation_failed")
			return
		}
		hash, err := secure.HashPassword(generated)
		if err != nil {
			httpjson.Error(w, http.StatusInternalServerError, "password_generation_failed")
			return
		}
		add("password_hash", hash)
		add("must_change_password", 1)
		temporary = generated
	}
	if len(sets) == 0 {
		httpjson.Error(w, http.StatusBadRequest, "nada_para_atualizar")
		return
	}
	add("updated_at", time.Now().UTC().Format(time.RFC3339))
	args = append(args, target.ID)
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(sets, ", "), len(args))
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_update_failed")
		return
	}

	// A disabled account (or one whose password was reset) must not keep
	// working with old sessions.
	if (body.Status != nil && *body.Status == "disabled") || body.ResetPassword {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, target.ID)
	}

	view, err := s.getUserView(ctx, target.ID)
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_update_failed")
		return
	}
	response := map[string]any{"user": view}
	if temporary != "" {
		response["temporary_password"] = temporary
	}
	httpjson.Write(w, http.StatusOK, response)
}

func (s *Service) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	current, _ := FromContext(ctx)
	if targetID == current.ID {
		httpjson.Error(w, http.StatusBadRequest, "não_excluir_a_si_mesmo")
		return
	}
	target, err := s.getUser(ctx, targetID)
	if err == sql.ErrNoRows {
		httpjson.Error(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_lookup_failed")
		return
	}
	if target.Role == "admin" {
		if err := s.ensureAnotherAdminExists(ctx, target.ID); err != nil {
			httpjson.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// ON DELETE CASCADE removes the account's sessions, vaults, entries,
	// API keys, backups and audit rows.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, target.ID); err != nil {
		httpjson.Error(w, http.StatusInternalServerError, "user_delete_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) ensureAnotherAdminExists(ctx context.Context, excludingID string) error {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active' AND id <> $1`,
		excludingID,
	).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("é preciso manter pelo menos um admin ativo")
	}
	return nil
}

func (s *Service) getUserView(ctx context.Context, id string) (UserView, error) {
	return scanUserView(s.db.QueryRowContext(ctx, `SELECT id, email, display_name, role, status, must_change_password, created_at
		FROM users WHERE id = $1`, id))
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUserView(row rowScanner) (UserView, error) {
	var view UserView
	var displayName sql.NullString
	var mustChange int
	if err := row.Scan(&view.ID, &view.Email, &displayName, &view.Role, &view.Status, &mustChange, &view.CreatedAt); err != nil {
		return UserView{}, err
	}
	view.DisplayName = displayName.String
	view.MustChangePassword = mustChange == 1
	return view, nil
}
