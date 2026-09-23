package admin

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	opdb "github.com/openpass/api/internal/db"
)

func TestLoginCreatesSessionCookieAndAllowsMiddleware(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")

	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"admin-pass"}`))
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

	protected := service.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("protected status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")

	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"wrong"}`))
	rec := httptest.NewRecorder()
	service.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "admin-pass") {
		t.Fatalf("response leaked configured password")
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	database := testDB(t)
	service := New(database, "admin-pass")
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

	// Try wrong current password
	changeReq := httptest.NewRequest(http.MethodPost, "/api/admin/change-password", strings.NewReader(`{"current_password":"wrong","new_password":"new-strong-pass"}`))
	changeRec := httptest.NewRecorder()
	service.ChangePassword(changeRec, changeReq)
	if changeRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for wrong current password", changeRec.Code)
	}

	// Change password correctly
	changeReq = httptest.NewRequest(http.MethodPost, "/api/admin/change-password", strings.NewReader(`{"current_password":"initial-pass","new_password":"new-strong-pass"}`))
	changeRec = httptest.NewRecorder()
	service.ChangePassword(changeRec, changeReq)
	if changeRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", changeRec.Code, changeRec.Body.String())
	}

	// Old password should fail
	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"initial-pass"}`))
	loginRec := httptest.NewRecorder()
	service.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, want 401", loginRec.Code)
	}

	// New password should succeed
	loginReq = httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"new-strong-pass"}`))
	loginRec = httptest.NewRecorder()
	service.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("new password status = %d, want 200", loginRec.Code)
	}
}

func TestRecoveryKeyFlow(t *testing.T) {
	database := testDB(t)
	service := New(database, "initial-pass")

	// Get recovery key
	recReq := httptest.NewRequest(http.MethodGet, "/api/admin/recovery-key", nil)
	recRec := httptest.NewRecorder()
	service.GetRecoveryKey(recRec, recReq)
	if recRec.Code != http.StatusOK {
		t.Fatalf("GetRecoveryKey status = %d, want 200", recRec.Code)
	}
	body := recRec.Body.String()
	if !strings.Contains(body, "OP-REC-") {
		t.Fatalf("body does not contain OP-REC- key: %s", body)
	}

	// Extract recovery key from body: {"recovery_key":"OP-REC-XXXX-XXXX-XXXX-XXXX"}
	idx := strings.Index(body, "OP-REC-")
	recoveryKey := body[idx : idx+26]

	// Try wrong recovery key
	recoverReq := httptest.NewRequest(http.MethodPost, "/api/admin/recover-password", strings.NewReader(`{"recovery_key":"WRONG-KEY","new_password":"recovered-pass"}`))
	recoverRec := httptest.NewRecorder()
	service.RecoverPassword(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for wrong recovery key", recoverRec.Code)
	}

	// Recover with correct key (even with lowercase or without dashes)
	recoverReq = httptest.NewRequest(http.MethodPost, "/api/admin/recover-password", strings.NewReader(`{"recovery_key":"`+strings.ToLower(recoveryKey)+`","new_password":"recovered-pass"}`))
	recoverRec = httptest.NewRecorder()
	service.RecoverPassword(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", recoverRec.Code, recoverRec.Body.String())
	}
	if len(recoverRec.Result().Cookies()) == 0 {
		t.Fatalf("RecoverPassword did not set session cookie")
	}

	// Verify login with recovered password
	loginReq := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"recovered-pass"}`))
	loginRec := httptest.NewRecorder()
	service.Login(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("recovered pass status = %d, want 200", loginRec.Code)
	}
}

func loginCookie(t *testing.T, service *Service) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login", strings.NewReader(`{"password":"admin-pass"}`))
	rec := httptest.NewRecorder()
	service.Login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Login status = %d, want 200", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login did not set a cookie")
	}
	return cookies[0]
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := opdb.Open(":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := opdb.Migrate(database, opdb.CoreSchema); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}
