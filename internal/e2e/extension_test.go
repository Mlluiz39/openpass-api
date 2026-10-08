// Package e2e exercises the HTTP surface the browser extension and the web
// panel actually talk to, over a real mux with real sessions and API keys.
//
// The unit tests next to each package check behaviour in isolation; this file
// checks that the routes are wired, the permissions line up and the JSON shapes
// match what the clients expect — the failure modes that only appear once the
// pieces are assembled.
package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openpass/api/internal/admin"
	"github.com/openpass/api/internal/apikeys"
	"github.com/openpass/api/internal/authenticator"
	"github.com/openpass/api/internal/chromeimport"
	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
	"github.com/openpass/api/internal/vault"
)

const (
	adminEmail    = "admin@e2e.test"
	adminPassword = "admin-pass"
	secretKey     = "e2e-secret"
	// The RFC 6238 SHA1 test secret, so expected codes are known good.
	totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

type harness struct {
	t      *testing.T
	db     *sql.DB
	mux    *http.ServeMux
	vault  *vault.Service
	keys   *apikeys.Service
	cookie *http.Cookie
	userID string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := opdb.OpenTest(t)

	adminSvc := admin.New(db, adminPassword, secretKey)
	if err := adminSvc.Bootstrap(adminEmail); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	keySvc := apikeys.New(db, secretKey)
	vaultSvc := vault.New(db, secretKey)

	mux := http.NewServeMux()
	adminSvc.RegisterRoutes(mux)
	keySvc.RegisterAdminRoutes(mux, adminSvc.Require)
	keySvc.RegisterAPIRoutes(mux)
	vaultSvc.RegisterAdminRoutes(mux, adminSvc.Require)
	vaultSvc.RegisterAPIRoutes(mux, keySvc)
	authSvc := authenticator.New(db, vaultSvc, secure.NewBox(secretKey))
	authSvc.RegisterAdminRoutes(mux, adminSvc.Require)
	authSvc.RegisterAPIRoutes(mux, keySvc)
	mux.Handle("POST /api/admin/import/chrome", adminSvc.Require(chromeimport.Handler(vaultSvc)))

	h := &harness{t: t, db: db, mux: mux, vault: vaultSvc, keys: keySvc}
	h.login()
	return h
}

func (h *harness) login() {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login",
		strings.NewReader(`{"email":"`+adminEmail+`","password":"`+adminPassword+`"}`))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("login status = %d, body=%s", rec.Code, rec.Body.String())
	}
	h.cookie = rec.Result().Cookies()[0]

	var id string
	if err := h.db.QueryRow(`SELECT id FROM users WHERE email = $1`, adminEmail).Scan(&id); err != nil {
		h.t.Fatalf("query admin id: %v", err)
	}
	h.userID = id
}

// do issues a request against the mux, adding the session cookie unless the
// caller already set an Authorization header.
func (h *harness) do(method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if _, ok := headers["Authorization"]; !ok && h.cookie != nil {
		req.AddCookie(h.cookie)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
}

// The panel flow: create an entry, attach a 2FA secret, read a code back.
func TestPanelCreatesEntryWithTOTPAndReadsCodes(t *testing.T) {
	h := newHarness(t)

	create := h.do(http.MethodPost, "/api/admin/entries",
		`{"path":"GitHub","type":"login","value":"s3nh4","metadata":{"username":"octocat","url":"https://github.com"}}`, nil)
	if create.Code != http.StatusCreated {
		t.Fatalf("create entry status = %d, body=%s", create.Code, create.Body.String())
	}
	var entry vault.Entry
	decode(t, create, &entry)
	if entry.ID == "" {
		t.Fatal("created entry has no id")
	}
	if entry.HasTOTP {
		t.Fatal("a fresh entry already reports has_totp")
	}

	setTOTP := h.do(http.MethodPut, "/api/admin/entries/"+entry.ID+"/totp",
		`{"secret":"`+totpSecret+`"}`, nil)
	if setTOTP.Code != http.StatusOK {
		t.Fatalf("set totp status = %d, body=%s", setTOTP.Code, setTOTP.Body.String())
	}
	var setBody struct {
		HasTOTP bool `json:"has_totp"`
	}
	decode(t, setTOTP, &setBody)
	if !setBody.HasTOTP {
		t.Fatalf("set totp response = %s, want has_totp true", setTOTP.Body.String())
	}

	code := h.do(http.MethodGet, "/api/admin/entries/"+entry.ID+"/code", "", nil)
	if code.Code != http.StatusOK {
		t.Fatalf("get code status = %d, body=%s", code.Code, code.Body.String())
	}
	var codeBody struct {
		Code             string `json:"code"`
		Period           int    `json:"period"`
		SecondsRemaining int    `json:"seconds_remaining"`
	}
	decode(t, code, &codeBody)
	if len(codeBody.Code) != 6 {
		t.Fatalf("code = %q, want 6 digits", codeBody.Code)
	}
	if codeBody.Period != 30 || codeBody.SecondsRemaining < 1 || codeBody.SecondsRemaining > 30 {
		t.Fatalf("period/remaining = %d/%d, want 30 and 1..30", codeBody.Period, codeBody.SecondsRemaining)
	}

	// The entry list must now advertise the secret's existence but never the
	// secret itself.
	list := h.do(http.MethodGet, "/api/admin/entries", "", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list entries status = %d", list.Code)
	}
	if strings.Contains(list.Body.String(), totpSecret) {
		t.Fatal("the entry list leaked the TOTP secret")
	}
	if !strings.Contains(list.Body.String(), `"has_totp":true`) {
		t.Fatalf("entry list does not report has_totp: %s", list.Body.String())
	}
}

func TestPanelRejectsAnInvalidTOTPSecret(t *testing.T) {
	h := newHarness(t)

	create := h.do(http.MethodPost, "/api/admin/entries", `{"path":"X","type":"login","value":"v"}`, nil)
	var entry vault.Entry
	decode(t, create, &entry)

	rec := h.do(http.MethodPut, "/api/admin/entries/"+entry.ID+"/totp", `{"secret":"não-é-base32!!"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid secret status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestPanelGeneratesPasswords(t *testing.T) {
	h := newHarness(t)

	rec := h.do(http.MethodGet, "/api/admin/password/generate?length=32&lower=1&upper=1&digits=1&symbols=1", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Password string `json:"password"`
		Strength int    `json:"strength"`
	}
	decode(t, rec, &body)
	if len([]rune(body.Password)) != 32 {
		t.Fatalf("password = %q (%d chars), want 32", body.Password, len([]rune(body.Password)))
	}
	if body.Strength <= 0 {
		t.Fatalf("strength = %d, want > 0", body.Strength)
	}

	// Two calls must not return the same value.
	second := h.do(http.MethodGet, "/api/admin/password/generate?length=32", "", nil)
	var body2 struct {
		Password string `json:"password"`
	}
	decode(t, second, &body2)
	if body.Password == body2.Password {
		t.Fatal("the generator returned the same password twice")
	}
}

// The extension flow: a scoped API key matches a URL, reveals on demand and
// fetches codes — and a look-alike host gets nothing.
func TestExtensionAPIFlow(t *testing.T) {
	h := newHarness(t)

	// An entry the extension should match.
	create := h.do(http.MethodPost, "/api/admin/entries",
		`{"path":"GitHub","type":"login","value":"s3nh4","metadata":{"username":"octocat","url":"https://github.com/login"}}`, nil)
	var entry vault.Entry
	decode(t, create, &entry)

	// A look-alike entry that must never answer for github.com.
	h.do(http.MethodPost, "/api/admin/entries",
		`{"path":"Evil","type":"login","value":"m4u","metadata":{"url":"https://github.com.evil.test"}}`, nil)

	created, err := h.keys.Create(context.Background(), h.userID, apikeys.CreateInput{
		Name:        "extensão",
		Permissions: map[string]bool{"entries:read": true, "entries:write": true},
	})
	if err != nil {
		t.Fatalf("Create key: %v", err)
	}
	auth := map[string]string{"Authorization": "Bearer " + created.Token}

	match := h.do(http.MethodGet, "/api/v1/entries/match?url=https://github.com/settings", "", auth)
	if match.Code != http.StatusOK {
		t.Fatalf("match status = %d, body=%s", match.Code, match.Body.String())
	}
	var matchBody struct {
		Data []struct {
			Entry struct {
				ID      string `json:"id"`
				Path    string `json:"path"`
				HasTOTP bool   `json:"has_totp"`
			} `json:"entry"`
			Value string `json:"value"`
		} `json:"data"`
	}
	decode(t, match, &matchBody)
	if len(matchBody.Data) != 1 {
		t.Fatalf("matched %d entries (%s), want only GitHub", len(matchBody.Data), match.Body.String())
	}
	if matchBody.Data[0].Entry.Path != "GitHub" {
		t.Fatalf("matched %q, want GitHub", matchBody.Data[0].Entry.Path)
	}
	if matchBody.Data[0].Value != "" {
		t.Fatalf("a plain match leaked the password: %q", matchBody.Data[0].Value)
	}

	reveal := h.do(http.MethodGet, "/api/v1/entries/match?url=https://github.com/settings&reveal=1", "", auth)
	var revealBody struct {
		Data []struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	decode(t, reveal, &revealBody)
	if len(revealBody.Data) != 1 || revealBody.Data[0].Value != "s3nh4" {
		t.Fatalf("reveal = %s, want the password", reveal.Body.String())
	}

	// A key without entries:write must not be able to create or generate.
	readOnly, err := h.keys.Create(context.Background(), h.userID, apikeys.CreateInput{
		Name:        "somente leitura",
		Permissions: map[string]bool{"entries:read": true},
	})
	if err != nil {
		t.Fatalf("Create read-only key: %v", err)
	}
	roAuth := map[string]string{"Authorization": "Bearer " + readOnly.Token}

	if rec := h.do(http.MethodPost, "/api/v1/entries", `{"path":"N","type":"login","value":"v"}`, roAuth); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only key created an entry: status %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec := h.do(http.MethodPost, "/api/v1/password/generate", `{}`, roAuth); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only key generated a password: status %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec := h.do(http.MethodPost, "/api/v1/password/generate", `{"length":24}`, auth); rec.Code != http.StatusOK {
		t.Fatalf("write key could not generate: status %d, body=%s", rec.Code, rec.Body.String())
	}

	// 2FA over the API: set the secret through the panel, read the code with
	// the key.
	setTOTP := h.do(http.MethodPut, "/api/admin/entries/"+entry.ID+"/totp", `{"secret":"`+totpSecret+`"}`, nil)
	if setTOTP.Code != http.StatusOK {
		t.Fatalf("set totp status = %d, body=%s", setTOTP.Code, setTOTP.Body.String())
	}

	code := h.do(http.MethodGet, "/api/v1/entries/"+entry.ID+"/code", "", auth)
	if code.Code != http.StatusOK {
		t.Fatalf("api code status = %d, body=%s", code.Code, code.Body.String())
	}
	var codeBody struct {
		Code string `json:"code"`
	}
	decode(t, code, &codeBody)
	if len(codeBody.Code) != 6 {
		t.Fatalf("api code = %q, want 6 digits", codeBody.Code)
	}

	// The look-alike URL must not receive the GitHub credentials.
	evil := h.do(http.MethodGet, "/api/v1/entries/match?url=https://github.com.evil.test/", "", auth)
	var evilBody struct {
		Data []struct {
			Entry struct {
				Path string `json:"path"`
			} `json:"entry"`
		} `json:"data"`
	}
	decode(t, evil, &evilBody)
	if len(evilBody.Data) != 1 || evilBody.Data[0].Entry.Path != "Evil" {
		t.Fatalf("look-alike match = %s, want only the Evil entry", evil.Body.String())
	}
}

func TestAPIRoutesRequireAKey(t *testing.T) {
	h := newHarness(t)

	// No Authorization header and no cookie: the extension routes must answer
	// 401, never data.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entries/match?url=https://github.com", nil)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated match status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// Importing a Chrome export must land the rows in the caller's vault, so the
// extension sees them immediately.
func TestChromeImportThenExtensionMatches(t *testing.T) {
	h := newHarness(t)

	csv := "name,url,username,password,note\n" +
		"GitHub,https://github.com,octocat,gh-pass,\n" +
		"Banco,https://meu.banco.com.br,me,banco-pass,\n"

	imp := h.do(http.MethodPost, "/api/admin/import/chrome",
		`{"csv":`+jsonString(csv)+`}`, nil)
	if imp.Code != http.StatusOK {
		t.Fatalf("import status = %d, body=%s", imp.Code, imp.Body.String())
	}
	var res struct {
		Imported int      `json:"imported"`
		Names    []string `json:"names"`
	}
	decode(t, imp, &res)
	if res.Imported != 2 {
		t.Fatalf("imported %d, want 2 (%v)", res.Imported, res.Names)
	}

	created, err := h.keys.Create(context.Background(), h.userID, apikeys.CreateInput{
		Name:        "extensão",
		Permissions: map[string]bool{"entries:read": true},
	})
	if err != nil {
		t.Fatalf("Create key: %v", err)
	}
	auth := map[string]string{"Authorization": "Bearer " + created.Token}

	match := h.do(http.MethodGet, "/api/v1/entries/match?url=https://github.com/login&reveal=1", "", auth)
	var body struct {
		Data []struct {
			Entry struct {
				Path string `json:"path"`
			} `json:"entry"`
			Value string `json:"value"`
		} `json:"data"`
	}
	decode(t, match, &body)
	if len(body.Data) != 1 {
		t.Fatalf("matched %d imported entries, want 1: %s", len(body.Data), match.Body.String())
	}
	if body.Data[0].Value != "gh-pass" {
		t.Fatalf("revealed %q, want gh-pass", body.Data[0].Value)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
