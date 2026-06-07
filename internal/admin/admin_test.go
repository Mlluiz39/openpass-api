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
