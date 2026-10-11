package bitwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openpass/api/internal/bitwarden/bwcrypto"
	opdb "github.com/openpass/api/internal/db"
)

const (
	testEmail    = "user@example.com"
	testPassword = "correct horse battery staple"
)

type client struct {
	t       *testing.T
	server  *httptest.Server
	token   string
	userKey []byte // unwrapped symmetric key, like a real client keeps locally
}

// newBitwardenTest builds a server over an isolated schema and provisions the
// test account exactly like the admin panel would.
func newBitwardenTest(t *testing.T) (*Service, *httptest.Server) {
	t.Helper()
	database := opdb.OpenTest(t)
	if _, err := database.Exec(
		`INSERT INTO users(id, email, display_name, password_hash, role, status, created_at, updated_at)
		 VALUES($1,$2,$3,$4,'user','active',$5,$5)`,
		"u-bw-1", testEmail, "Pessoa Teste", "argon2id$placeholder", time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	service := New(database, "")
	if err := service.ProvisionUser(context.Background(), "u-bw-1", testPassword); err != nil {
		t.Fatalf("ProvisionUser: %v", err)
	}
	mux := http.NewServeMux()
	service.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return service, server
}

func (c *client) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, c.server.URL+path, reader)
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	return response, payload
}

func (c *client) doForm(path string, values map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	form := url.Values{}
	for key, value := range values {
		form.Set(key, value)
	}
	request, err := http.NewRequest("POST", c.server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t := c.t
		t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	return response, payload
}

// login simulates the client side of a Bitwarden login: derive the master
// key locally, then hand the server only the derived material.
func (c *client) login(extra map[string]string) map[string]any {
	c.t.Helper()
	masterKey, err := bwcrypto.DeriveMasterKey(testPassword, bwcrypto.NormalizeSalt(testEmail), bwcrypto.DefaultKDF())
	if err != nil {
		c.t.Fatalf("derive master key: %v", err)
	}
	values := map[string]string{
		"grant_type":        "password",
		"username":          testEmail,
		"password":          base64.StdEncoding.EncodeToString(masterKey),
		"scope":             "api offline_access",
		"client_id":         "web",
		"device_identifier": "device-1",
		"device_name":       "Firefox",
		"device_type":       "8",
	}
	for key, value := range extra {
		values[key] = value
	}
	response, payload := c.doForm("/identity/connect/token", values)
	if response.StatusCode != http.StatusOK {
		c.t.Fatalf("login status = %d, body = %s", response.StatusCode, payload)
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		c.t.Fatalf("parse token response: %v", err)
	}
	c.token, _ = parsed["access_token"].(string)
	if c.token == "" {
		c.t.Fatalf("no access token in response: %s", payload)
	}
	// Unwrap the symmetric user key exactly like the client does.
	wrapped, _ := parsed["Key"].(string)
	userKey, err := bwcrypto.UnwrapUserKey(masterKey, wrapped)
	if err != nil {
		c.t.Fatalf("unwrap user key: %v", err)
	}
	c.userKey = userKey
	return parsed
}

func (c *client) encrypt(value string) string {
	c.t.Helper()
	encoded, err := bwcrypto.Encrypt(c.userKey, []byte(value))
	if err != nil {
		c.t.Fatalf("encrypt: %v", err)
	}
	return encoded
}

func TestLoginSyncAndCipherLifecycle(t *testing.T) {
	_, server := newBitwardenTest(t)
	client := &client{t: t, server: server}

	// Prelogin returns the KDF settings the client needs before deriving.
	response, payload := client.do("POST", "/identity/accounts/prelogin", map[string]string{"email": testEmail})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("prelogin status = %d, body = %s", response.StatusCode, payload)
	}
	var prelogin map[string]any
	_ = json.Unmarshal(payload, &prelogin)
	if int(prelogin["kdf"].(float64)) != bwcrypto.KdfPBKDF2SHA256 {
		t.Fatalf("prelogin kdf = %v, want PBKDF2", prelogin["kdf"])
	}
	if int(prelogin["kdfIterations"].(float64)) != bwcrypto.DefaultKDFIterations {
		t.Fatalf("prelogin iterations = %v", prelogin["kdfIterations"])
	}

	tokens := client.login(nil)
	for _, field := range []string{"Key", "PrivateKey", "Kdf", "KdfIterations", "refresh_token"} {
		if tokens[field] == nil {
			t.Fatalf("token response missing %q: %v", field, tokens)
		}
	}

	// Sync returns the profile plus empty collections for a fresh account.
	response, payload = client.do("GET", "/api/sync?excludeDomains=true", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("sync status = %d, body = %s", response.StatusCode, payload)
	}
	var sync map[string]any
	_ = json.Unmarshal(payload, &sync)
	if sync["object"] != "sync" {
		t.Fatalf("sync object = %v", sync["object"])
	}
	profile, _ := sync["profile"].(map[string]any)
	if profile["email"] != testEmail {
		t.Fatalf("profile email = %v", profile["email"])
	}

	// Folder CRUD.
	response, payload = client.do("POST", "/api/folders", map[string]any{"name": client.encrypt("Trabalho")})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create folder status = %d, body = %s", response.StatusCode, payload)
	}
	var folder map[string]any
	_ = json.Unmarshal(payload, &folder)
	folderID, _ := folder["id"].(string)
	if folderID == "" {
		t.Fatalf("folder without id: %s", payload)
	}

	encURI := client.encrypt("https://banco.example.com")
	// Cipher create (login item), like the extension would send it.
	response, payload = client.do("POST", "/api/ciphers", map[string]any{
		"type":     1,
		"folderId": folderID,
		"name":     client.encrypt("Banco"),
		"notes":    client.encrypt("nota"),
		"favorite": true,
		"reprompt": 0,
		"login": map[string]any{
			"username": client.encrypt("maria"),
			"password": client.encrypt("segredo"),
			"totp":     client.encrypt("otpauth://totp/Banco"),
			"uris":     []any{map[string]any{"uri": encURI}},
		},
		"fields": []any{map[string]any{"name": client.encrypt("agencia"), "value": client.encrypt("1234"), "type": 1}},
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create cipher status = %d, body = %s", response.StatusCode, payload)
	}
	var cipher map[string]any
	_ = json.Unmarshal(payload, &cipher)
	cipherID, _ := cipher["id"].(string)
	if cipherID == "" {
		t.Fatalf("cipher without id: %s", payload)
	}
	if cipher["object"] != "cipherDetails" {
		t.Fatalf("cipher object = %v", cipher["object"])
	}
	login, _ := cipher["login"].(map[string]any)
	if login["uri"] != encURI {
		t.Fatalf("login uri = %v, want the stored uri", login["uri"])
	}
	if cipher["folderId"] != folderID {
		t.Fatalf("cipher folderId = %v, want %v", cipher["folderId"], folderID)
	}
	if cipher["favorite"] != true {
		t.Fatalf("cipher favorite = %v", cipher["favorite"])
	}

	// The TOTP sentinel endpoint lists ciphers carrying a totp field.
	response, payload = client.do("GET", "/api/ciphers/"+totpCollectionID, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("totp list status = %d, body = %s", response.StatusCode, payload)
	}
	var totpList map[string]any
	_ = json.Unmarshal(payload, &totpList)
	if data, _ := totpList["data"].([]any); len(data) != 1 {
		t.Fatalf("totp list len = %d, want 1 (%s)", len(data), payload)
	}

	// Favorite toggle.
	response, payload = client.do("PUT", "/api/ciphers/"+cipherID+"/favorite", map[string]any{"favorite": false})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("favorite status = %d, body = %s", response.StatusCode, payload)
	}
	_ = json.Unmarshal(payload, &cipher)
	if cipher["favorite"] != false {
		t.Fatalf("favorite after toggle = %v", cipher["favorite"])
	}

	// Trash → list still returns it (with deletedDate) → restore → delete.
	response, payload = client.do("POST", "/api/ciphers/"+cipherID+"/delete", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("trash status = %d, body = %s", response.StatusCode, payload)
	}
	response, payload = client.do("GET", "/api/ciphers/"+cipherID, nil)
	_ = json.Unmarshal(payload, &cipher)
	if cipher["deletedDate"] == nil {
		t.Fatalf("trashed cipher has no deletedDate: %s", payload)
	}
	response, payload = client.do("POST", "/api/ciphers/"+cipherID+"/restore", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restore status = %d, body = %s", response.StatusCode, payload)
	}
	_ = json.Unmarshal(payload, &cipher)
	if cipher["deletedDate"] != nil {
		t.Fatalf("restored cipher still has deletedDate: %s", payload)
	}

	// Update the cipher and verify the stale-write guard accepts a fresh
	// revision date.
	revision, _ := cipher["revisionDate"].(string)
	response, payload = client.do("PUT", "/api/ciphers/"+cipherID, map[string]any{
		"type":                  1,
		"name":                  client.encrypt("Banco Editado"),
		"login":                 map[string]any{"username": client.encrypt("maria")},
		"lastKnownRevisionDate": revision,
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", response.StatusCode, payload)
	}

	// Permanent deletion.
	response, payload = client.do("DELETE", "/api/ciphers/"+cipherID, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", response.StatusCode, payload)
	}
	response, payload = client.do("GET", "/api/ciphers/"+cipherID, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted cipher status = %d, want 404 (%s)", response.StatusCode, payload)
	}

	// Folder deletion.
	response, payload = client.do("DELETE", "/api/folders/"+folderID, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("delete folder status = %d, body = %s", response.StatusCode, payload)
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	_, server := newBitwardenTest(t)
	client := &client{t: t, server: server}
	tokens := client.login(nil)
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("no refresh token issued")
	}

	response, payload := client.doForm("/identity/connect/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     "web",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", response.StatusCode, payload)
	}
	var rotated map[string]any
	_ = json.Unmarshal(payload, &rotated)
	newRefresh, _ := rotated["refresh_token"].(string)
	if newRefresh == "" || newRefresh == refresh {
		t.Fatalf("refresh token was not rotated: %s", payload)
	}

	// The old token must stop working after rotation.
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     "web",
	})
	if response.StatusCode == http.StatusOK {
		t.Fatalf("old refresh token still accepted: %s", payload)
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	_, server := newBitwardenTest(t)
	client := &client{t: t, server: server}

	wrongKey, err := bwcrypto.DeriveMasterKey("errada", bwcrypto.NormalizeSalt(testEmail), bwcrypto.DefaultKDF())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	response, payload := client.doForm("/identity/connect/token", map[string]string{
		"grant_type":        "password",
		"username":          testEmail,
		"password":          base64.StdEncoding.EncodeToString(wrongKey),
		"scope":             "api offline_access",
		"client_id":         "web",
		"device_identifier": "d",
		"device_name":       "x",
		"device_type":       "8",
	})
	if response.StatusCode == http.StatusOK {
		t.Fatalf("wrong password accepted: %s", payload)
	}
	if !strings.Contains(string(payload), "Username or password is incorrect") {
		t.Fatalf("unexpected error body: %s", payload)
	}

	// Unauthenticated /api calls must be rejected.
	request, _ := http.NewRequest("GET", server.URL+"/api/sync", nil)
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("sync request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated sync status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthenticatorTwoFactorLogin(t *testing.T) {
	_, server := newBitwardenTest(t)
	client := &client{t: t, server: server}
	client.login(nil)

	// Enroll: fetch a secret, then confirm a valid code.
	response, payload := client.do("POST", "/api/settings/two-factor/authenticator", map[string]any{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("enable 2fa status = %d, body = %s", response.StatusCode, payload)
	}
	var enrollment map[string]any
	_ = json.Unmarshal(payload, &enrollment)
	secret, _ := enrollment["Secret"].(string)
	if secret == "" {
		t.Fatalf("no 2fa secret: %s", payload)
	}

	code := testTOTPCode(t, secret)
	response, payload = client.do("POST", "/api/settings/two-factor/authenticator/confirm", map[string]any{"code": code})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("confirm 2fa status = %d, body = %s", response.StatusCode, payload)
	}

	// A fresh login without a code must be challenged.
	client.token = ""
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":        "password",
		"username":          testEmail,
		"password":          base64.StdEncoding.EncodeToString(mustMasterKey(t)),
		"scope":             "api offline_access",
		"client_id":         "web",
		"device_identifier": "device-2",
		"device_name":       "Chrome",
		"device_type":       "8",
	})
	if response.StatusCode == http.StatusOK {
		t.Fatalf("login without 2fa code accepted: %s", payload)
	}
	var challenge map[string]any
	_ = json.Unmarshal(payload, &challenge)
	providers, _ := challenge["TwoFactorProviders"].([]any)
	if len(providers) == 0 {
		t.Fatalf("no 2FA providers advertised: %s", payload)
	}

	// Retrying with the code and remember=1 succeeds and returns a token.
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":          "password",
		"username":            testEmail,
		"password":            base64.StdEncoding.EncodeToString(mustMasterKey(t)),
		"scope":               "api offline_access",
		"client_id":           "web",
		"device_identifier":   "device-2",
		"device_name":         "Chrome",
		"device_type":         "8",
		"two_factor_provider": "0",
		"two_factor_token":    testTOTPCode(t, secret),
		"two_factor_remember": "1",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login with 2fa code status = %d, body = %s", response.StatusCode, payload)
	}
	var tokens map[string]any
	_ = json.Unmarshal(payload, &tokens)
	remember, _ := tokens["TwoFactorToken"].(string)
	if remember == "" {
		t.Fatalf("no remember token issued: %s", payload)
	}

	// The remember token now bypasses the challenge.
	client.token = ""
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":          "password",
		"username":            testEmail,
		"password":            base64.StdEncoding.EncodeToString(mustMasterKey(t)),
		"scope":               "api offline_access",
		"client_id":           "web",
		"device_identifier":   "device-2",
		"device_name":         "Chrome",
		"device_type":         "8",
		"two_factor_provider": fmt.Sprintf("%d", twoFactorProviderRemember),
		"two_factor_token":    remember,
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login with remember token status = %d, body = %s", response.StatusCode, payload)
	}
	var remembered map[string]any
	_ = json.Unmarshal(payload, &remembered)
	client.token, _ = remembered["access_token"].(string)
	if client.token == "" {
		t.Fatalf("no access token after remember login: %s", payload)
	}

	// Disable 2FA again to leave the account as it was.
	response, payload = client.do("POST", "/api/settings/two-factor/disable", map[string]any{
		"masterPasswordHash": mustMasterHash(t),
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable 2fa status = %d, body = %s", response.StatusCode, payload)
	}
}

func TestMasterPasswordChange(t *testing.T) {
	_, server := newBitwardenTest(t)
	client := &client{t: t, server: server}
	tokens := client.login(nil)
	wrapped, _ := tokens["Key"].(string)

	newMasterKey, err := bwcrypto.DeriveMasterKey("nova senha mestre", bwcrypto.NormalizeSalt(testEmail), bwcrypto.DefaultKDF())
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	newWrapped, err := bwcrypto.WrapUserKey(newMasterKey, client.userKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	response, payload := client.do("POST", "/api/accounts/password", map[string]any{
		"masterPasswordHash":    mustMasterHash(t),
		"newMasterPasswordHash": bwcrypto.HashMasterKey(newMasterKey, bwcrypto.NormalizeSalt(testEmail)),
		"key":                   newWrapped,
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d, body = %s", response.StatusCode, payload)
	}
	_ = wrapped

	// The old master password must no longer work; the new one must.
	oldKey := mustMasterKey(t)
	masterKey, _ := bwcrypto.DeriveMasterKey("nova senha mestre", bwcrypto.NormalizeSalt(testEmail), bwcrypto.DefaultKDF())
	masterKeyHash := bwcrypto.HashMasterKey(masterKey, bwcrypto.NormalizeSalt(testEmail))
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":        "password",
		"username":          testEmail,
		"password":          base64.StdEncoding.EncodeToString(oldKey),
		"scope":             "api offline_access",
		"client_id":         "web",
		"device_identifier": "d3",
		"device_name":       "x",
		"device_type":       "8",
	})
	if response.StatusCode == http.StatusOK {
		t.Fatalf("old master password still accepted: %s", payload)
	}
	response, payload = client.doForm("/identity/connect/token", map[string]string{
		"grant_type":        "password",
		"username":          testEmail,
		"password":          base64.StdEncoding.EncodeToString(masterKey),
		"scope":             "api offline_access",
		"client_id":         "web",
		"device_identifier": "d3",
		"device_name":       "x",
		"device_type":       "8",
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("new master password rejected: %d %s", response.StatusCode, payload)
	}
	_ = masterKeyHash
}

// decodeBase32Secret decodes an enrollment secret the same way an
// authenticator app would.
func decodeBase32Secret(secret string) ([]byte, error) {
	return otpAlphabet.DecodeString(strings.ToUpper(secret))
}

func mustMasterKey(t *testing.T) []byte {
	t.Helper()
	key, err := bwcrypto.DeriveMasterKey(testPassword, bwcrypto.NormalizeSalt(testEmail), bwcrypto.DefaultKDF())
	if err != nil {
		t.Fatalf("derive master key: %v", err)
	}
	return key
}

func mustMasterHash(t *testing.T) string {
	t.Helper()
	return bwcrypto.HashMasterKey(mustMasterKey(t), bwcrypto.NormalizeSalt(testEmail))
}

// testTOTPCode computes a valid code for the enrolled secret, reusing the
// server's HOTP primitive (same package).
func testTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	key, err := decodeBase32Secret(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(time.Now().UTC().Unix() / 30)
	return hotp(key, counter)
}
