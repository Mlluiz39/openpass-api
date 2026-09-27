package admin

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
)

const adminEmail = "admin@test.local"

func TestBootstrapLoginCreatesSessionAndRequireInjectsUser(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"email":"`+adminEmail+`","password":"admin-pass"}`))
	loginRec := httptest.NewRecorder()
	service.Login(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("Login status = %d, want 200; body=%s", loginRec.Code, loginRec.Body.String())
	}
	cookie := loginRec.Result().Cookies()[0]
	if cookie.Name != CookieName {
		t.Fatalf("cookie name = %q, want %q", cookie.Name, CookieName)
	}
	if !cookie.HttpOnly {
		t.Fatalf("session cookie must be HTTP-only")
	}

	var seen *CurrentUser
	protected := service.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := FromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		seen = user
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if seen == nil || seen.Email != adminEmail || !seen.IsAdmin() {
		t.Fatalf("context user = %+v, want admin %s", seen, adminEmail)
	}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if err := service.Bootstrap("other@test.local"); err != nil {
		t.Fatalf("second Bootstrap() error = %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 1 {
		t.Fatalf("users = %d, want 1 (bootstrap must only run on an empty table)", count)
	}
}

func TestLoginRejectsWrongPasswordAndUnknownEmail(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	for _, body := range []string{
		`{"email":"` + adminEmail + `","password":"wrong"}`,
		`{"email":"nobody@test.local","password":"admin-pass"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(body))
		rec := httptest.NewRecorder()
		service.Login(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d for %s, want 401", rec.Code, body)
		}
		if strings.Contains(rec.Body.String(), "admin-pass") {
			t.Fatalf("response leaked configured password")
		}
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	cookie := loginCookie(t, service)

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/admin/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	service.Require(http.HandlerFunc(service.Logout)).ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("Logout status = %d, want 200", logoutRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	service.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("protected status after logout = %d, want 401", rec.Code)
	}
}

func TestChangePasswordAndLogin(t *testing.T) {
	database := testDB(t)
	service := New(database, "initial-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	cookie := loginCookie(t, service, `{"email":"`+adminEmail+`","password":"initial-pass"}`)

	// Wrong current password.
	rec := callAuthed(t, service, cookie, http.MethodPost, "/api/admin/change-password",
		`{"current_password":"wrong","new_password":"new-strong-pass"}`, service.ChangePassword)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for wrong current password", rec.Code)
	}

	// Correct change.
	rec = callAuthed(t, service, cookie, http.MethodPost, "/api/admin/change-password",
		`{"current_password":"initial-pass","new_password":"new-strong-pass"}`, service.ChangePassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Old password fails, new one works.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"email":"`+adminEmail+`","password":"initial-pass"}`))
	got := httptest.NewRecorder()
	service.Login(got, req)
	if got.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", got.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"email":"`+adminEmail+`","password":"new-strong-pass"}`))
	got = httptest.NewRecorder()
	service.Login(got, req)
	if got.Code != http.StatusOK {
		t.Fatalf("new password status = %d, want 200", got.Code)
	}
}

func TestRecoveryKeyFlow(t *testing.T) {
	database := testDB(t)
	service := New(database, "initial-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	cookie := loginCookie(t, service, `{"email":"`+adminEmail+`","password":"initial-pass"}`)

	rec := callAuthed(t, service, cookie, http.MethodGet, "/api/admin/recovery-key", "", service.GetRecoveryKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetRecoveryKey status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "OP-REC-") {
		t.Fatalf("body does not contain OP-REC- key: %s", body)
	}
	idx := strings.Index(body, "OP-REC-")
	recoveryKey := body[idx : idx+26]

	// Wrong recovery key (with e-mail): 401.
	recoverReq := httptest.NewRequest(http.MethodPost, "/api/admin/recover-password",
		strings.NewReader(`{"email":"`+adminEmail+`","recovery_key":"WRONG-KEY","new_password":"recovered-pass"}`))
	recoverRec := httptest.NewRecorder()
	service.RecoverPassword(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong recovery key", recoverRec.Code)
	}

	// Unknown e-mail: rejected the same way.
	recoverReq = httptest.NewRequest(http.MethodPost, "/api/admin/recover-password",
		strings.NewReader(`{"email":"nobody@test.local","recovery_key":"`+recoveryKey+`","new_password":"recovered-pass"}`))
	recoverRec = httptest.NewRecorder()
	service.RecoverPassword(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown e-mail", recoverRec.Code)
	}

	// Correct key (lowercase, no formatting issues) succeeds and sets a cookie.
	recoverReq = httptest.NewRequest(http.MethodPost, "/api/admin/recover-password",
		strings.NewReader(`{"email":"`+adminEmail+`","recovery_key":"`+strings.ToLower(recoveryKey)+`","new_password":"recovered-pass"}`))
	recoverRec = httptest.NewRecorder()
	service.RecoverPassword(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recoverRec.Code, recoverRec.Body.String())
	}
	if len(recoverRec.Result().Cookies()) == 0 {
		t.Fatalf("RecoverPassword did not set session cookie")
	}

	// Login with the recovered password works.
	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"email":"`+adminEmail+`","password":"recovered-pass"}`))
	loginRec := httptest.NewRecorder()
	service.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("recovered pass status = %d, want 200", loginRec.Code)
	}
}

func TestNormalizeRecoveryKeyAcceptsCommonFormats(t *testing.T) {
	const body = "5DRR992HJABKLS4C"
	formatted := "OP-REC-5DRR-992H-JABK-LS4C"
	for _, input := range []string{
		formatted,
		strings.ToLower(formatted),
		body,
		strings.ToLower(body),
		"op rec 5drr 992h jabk ls4c",
		"  OP-REC-5DRR-992H-JABK-LS4C  ",
	} {
		if got := normalizeRecoveryKey(input); got != body {
			t.Fatalf("normalizeRecoveryKey(%q) = %q, want %q", input, got, body)
		}
	}
}

func TestRecoveryKeyAcceptsUnformattedInput(t *testing.T) {
	database := testDB(t)
	service := New(database, "initial-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	key, err := service.generateAndSaveRecoveryKey(context.Background(), firstUserID(t, database))
	if err != nil {
		t.Fatalf("generateAndSaveRecoveryKey() error = %v", err)
	}

	flattened := strings.ToLower(strings.ReplaceAll(key, "-", ""))
	req := httptest.NewRequest(http.MethodPost, "/api/admin/recover-password",
		strings.NewReader(`{"email":"`+adminEmail+`","recovery_key":"`+flattened+`","new_password":"recovered-pass"}`))
	rec := httptest.NewRecorder()
	service.RecoverPassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for unformatted key; body=%s", rec.Code, rec.Body.String())
	}
}

func TestResetPasswordRestoresConfiguredPassword(t *testing.T) {
	database := testDB(t)
	service := New(database, "configured-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	// Simulate a password changed from the panel.
	userID := firstUserID(t, database)
	if err := service.setNewPassword(context.Background(), userID, "panel-chosen-pass"); err != nil {
		t.Fatalf("setNewPassword() error = %v", err)
	}

	login := func(password string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
			strings.NewReader(`{"email":"`+adminEmail+`","password":"`+password+`"}`))
		rec := httptest.NewRecorder()
		service.Login(rec, req)
		return rec.Code
	}

	if got := login("configured-pass"); got != http.StatusUnauthorized {
		t.Fatalf("configured pass after panel change = %d, want 401", got)
	}

	if err := service.ResetPassword(); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	if got := login("configured-pass"); got != http.StatusOK {
		t.Fatalf("configured pass after reset = %d, want 200", got)
	}
	if got := login("panel-chosen-pass"); got != http.StatusUnauthorized {
		t.Fatalf("old panel pass after reset = %d, want 401", got)
	}
}

func TestResetPasswordDropsExistingSessions(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
	if err := service.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	cookie := loginCookie(t, service)

	if err := service.ResetPassword(); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	service.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after reset = %d, want 401", rec.Code)
	}
}

// The single-admin era stored SHA-256(salt:password) in app_settings; the
// migration tool writes that as legacy-sha256:salt:hash. Such an account must
// still log in, and the stored hash must be upgraded to argon2id on success.
func TestLegacyPasswordHashIsVerifiedAndUpgraded(t *testing.T) {
	database := testDB(t)
	service := New(database, "ignored")
	salt, hash := "0123456789abcdef", secure.SHA256Hex("0123456789abcdef:legacy-pass")
	_, err := database.Exec(`INSERT INTO users(id, email, password_hash, role, status, must_change_password, created_at, updated_at)
		VALUES('u-legacy', 'legacy@test.local', $1, 'admin', 'active', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
		"legacy-sha256:"+salt+":"+hash)
	if err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
		strings.NewReader(`{"email":"legacy@test.local","password":"legacy-pass"}`))
	rec := httptest.NewRecorder()
	service.Login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var stored string
	if err := database.QueryRow(`SELECT password_hash FROM users WHERE id = 'u-legacy'`).Scan(&stored); err != nil {
		t.Fatalf("read stored hash: %v", err)
	}
	if !strings.HasPrefix(stored, "argon2id$") {
		t.Fatalf("stored hash = %q, want argon2id$... after rehash", stored)
	}
	if stored == "legacy-sha256:"+salt+":"+hash {
		t.Fatalf("legacy hash was not upgraded")
	}
}

func loginCookie(t *testing.T, service *Service, body ...string) *http.Cookie {
	t.Helper()
	payload := `{"email":"` + adminEmail + `","password":"admin-pass"}`
	if len(body) > 0 {
		payload = body[0]
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	service.Login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login did not set a cookie")
	}
	return cookies[0]
}

// callAuthed runs a handler through Require so the session user is present in
// the context, exactly like the real route wiring.
func callAuthed(t *testing.T, service *Service, cookie *http.Cookie, method, path, body string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	service.Require(handler).ServeHTTP(rec, req)
	return rec
}

func firstUserID(t *testing.T, database *sql.DB) string {
	t.Helper()
	var id string
	if err := database.QueryRow(`SELECT id FROM users ORDER BY created_at ASC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	return id
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	return opdb.OpenTest(t)
}
