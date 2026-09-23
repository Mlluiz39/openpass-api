package apikeys

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openpass/api/internal/audit"
	opdb "github.com/openpass/api/internal/db"
	"github.com/openpass/api/internal/secure"
)

func TestCreateRevealAndAuthenticateKey(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	created, err := service.Create(context.Background(), CreateInput{
		Name:         "Claude Code",
		Env:          "live",
		Permissions:  map[string]bool{"vaults:read": true},
		RateLimitRPM: 60,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Token == "" {
		t.Fatalf("Create() returned empty token")
	}
	if created.KeyPrefix != created.Token[:16] {
		t.Fatalf("KeyPrefix = %q, want token prefix", created.KeyPrefix)
	}

	var encryptedToken, keyHash string
	if err := database.QueryRow(
		`SELECT encrypted_token, key_hash FROM api_keys WHERE id = ?`,
		created.ID,
	).Scan(&encryptedToken, &keyHash); err != nil {
		t.Fatalf("query created key: %v", err)
	}
	if encryptedToken == created.Token {
		t.Fatalf("token stored in plaintext")
	}
	if !secure.VerifySHA256(created.Token, keyHash) {
		t.Fatalf("stored hash does not match token")
	}

	revealed, err := service.Reveal(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Reveal() error = %v", err)
	}
	if revealed != created.Token {
		t.Fatalf("Reveal() = %q, want original token", revealed)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "203.0.113.7:4444"
	auth, status, err := service.Authenticate(req, "vaults:read")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Authenticate() status=%d err=%v", status, err)
	}
	if auth.ID != created.ID {
		t.Fatalf("authenticated key id = %q, want %q", auth.ID, created.ID)
	}
}

func TestCreateKeyWithoutPrefixAndAuthenticate(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	created, err := service.Create(context.Background(), CreateInput{
		Name:        "Raw Hex Key",
		Env:         "none",
		Permissions: map[string]bool{"vaults:read": true},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(created.Token) != 48 {
		t.Fatalf("Token length = %d, want 48 hex chars", len(created.Token))
	}
	if created.KeyPrefix != created.Token[:16] {
		t.Fatalf("KeyPrefix = %q, want %q", created.KeyPrefix, created.Token[:16])
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "203.0.113.7:4444"
	auth, status, err := service.Authenticate(req, "vaults:read")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Authenticate() status=%d err=%v", status, err)
	}
	if auth.ID != created.ID {
		t.Fatalf("authenticated key id = %q, want %q", auth.ID, created.ID)
	}
}

func TestCreateKeyWithCustomTokenAndAuthenticate(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")

	customToken := "my-secret-agent-api-token-custom"
	created, err := service.Create(context.Background(), CreateInput{
		Name:        "Custom Key",
		Token:       customToken,
		Permissions: map[string]bool{"vaults:read": true},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Token != customToken {
		t.Fatalf("Token = %q, want %q", created.Token, customToken)
	}

	revealed, err := service.Reveal(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Reveal() error = %v", err)
	}
	if revealed != customToken {
		t.Fatalf("Reveal() = %q, want %q", revealed, customToken)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+customToken)
	req.RemoteAddr = "203.0.113.7:4444"
	auth, status, err := service.Authenticate(req, "vaults:read")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Authenticate() status=%d err=%v", status, err)
	}
	if auth.ID != created.ID {
		t.Fatalf("authenticated key id = %q, want %q", auth.ID, created.ID)
	}
}

func TestRevokedKeyCannotAuthenticate(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	created, err := service.Create(context.Background(), CreateInput{
		Name:        "Agent",
		Env:         "live",
		Permissions: map[string]bool{"vaults:read": true},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := service.Revoke(context.Background(), created.ID); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	_, status, err := service.Authenticate(req, "vaults:read")
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("Authenticate() status=%d err=%v, want 401 error", status, err)
	}
}

func TestPermissionAllowedIPVaultScopeAndRateLimit(t *testing.T) {
	database := testDB(t)
	service := New(database, "secret")
	created, err := service.Create(context.Background(), CreateInput{
		Name:         "Scoped Agent",
		Env:          "live",
		Permissions:  map[string]bool{"entries:read": true},
		AllowedIPs:   []string{"203.0.113.0/24"},
		VaultScope:   []string{"vault-1"},
		RateLimitRPM: 1,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "198.51.100.9:5555"
	_, status, err := service.Authenticate(req, "entries:read")
	if err == nil || status != http.StatusUnauthorized {
		t.Fatalf("blocked IP status=%d err=%v, want 401", status, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "203.0.113.8:5555"
	_, status, err = service.Authenticate(req, "entries:write")
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("missing permission status=%d err=%v, want 403", status, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "203.0.113.8:5555"
	auth, status, err := service.Authenticate(req, "entries:read")
	if err != nil || status != http.StatusOK {
		t.Fatalf("allowed auth status=%d err=%v", status, err)
	}
	if !auth.CanAccessVault("vault-1") {
		t.Fatalf("expected access to vault-1")
	}
	if auth.CanAccessVault("vault-2") {
		t.Fatalf("unexpected access to vault-2")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.RemoteAddr = "203.0.113.8:5555"
	_, status, err = service.Authenticate(req, "entries:read")
	if err == nil || status != http.StatusTooManyRequests {
		t.Fatalf("second request status=%d err=%v, want 429", status, err)
	}
}

func TestRequirePermissionRecordsAuditForDeniedAndSuccess(t *testing.T) {
	database := testDB(t)
	auditService := audit.New(database)
	service := New(database, "secret")
	service.SetAudit(auditService)
	created, err := service.Create(context.Background(), CreateInput{
		Name:        "Audited Agent",
		Env:         "live",
		Permissions: map[string]bool{"vaults:read": true},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	handler := service.RequirePermission("vaults:read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	deniedReq := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	deniedReq.Header.Set("Authorization", "Bearer op_live_badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad")
	deniedRec := httptest.NewRecorder()
	handler.ServeHTTP(deniedRec, deniedReq)
	if deniedRec.Code != http.StatusUnauthorized {
		t.Fatalf("denied status = %d, want 401", deniedRec.Code)
	}

	successReq := httptest.NewRequest(http.MethodGet, "/api/v1/vaults", nil)
	successReq.Header.Set("Authorization", "Bearer "+created.Token)
	successRec := httptest.NewRecorder()
	handler.ServeHTTP(successRec, successReq)
	if successRec.Code != http.StatusNoContent {
		t.Fatalf("success status = %d, want 204", successRec.Code)
	}

	denied, err := auditService.List(context.Background(), audit.Filter{Result: "denied"})
	if err != nil {
		t.Fatalf("List(denied) error = %v", err)
	}
	if len(denied) != 1 {
		t.Fatalf("denied logs = %d, want 1", len(denied))
	}
	success, err := auditService.List(context.Background(), audit.Filter{Result: "success"})
	if err != nil {
		t.Fatalf("List(success) error = %v", err)
	}
	if len(success) != 1 || success[0].APIKeyID == nil || *success[0].APIKeyID != created.ID {
		t.Fatalf("success logs = %+v, want one log with api key id", success)
	}
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
