package bitwarden

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openpass/api/internal/bitwarden/bwcrypto"
)

// serverVersion is reported to clients for backwards-compatibility
// decisions; it tracks the upstream server version the API shapes mirror.
const serverVersion = "2026.6.0"

// twoFactorProviderRemember is the pseudo provider clients use to present a
// previously issued "remember this device" token.
const twoFactorProviderRemember = -2

// handleOpenIDConfiguration serves the OIDC discovery document; clients use
// it to locate the token endpoint and the JWKS.
func (s *Service) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	domain := domainFromRequest(r, s.domainOverride)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                domain + "/identity",
		"authorization_endpoint":                domain + "/identity/connect/authorize",
		"token_endpoint":                        domain + "/identity/connect/token",
		"end_session_endpoint":                  domain + "/identity/connect/endsession",
		"jwks_uri":                              domain + "/identity/keys",
		"scopes_supported":                      []string{"api", "offline_access"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "scope", "client_id"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "password"},
	})
}

// handleKeys serves the JSON Web Key Set used to verify access tokens.
func (s *Service) handleKeys(w http.ResponseWriter, r *http.Request) {
	key, err := s.loadOrCreateServiceKey(r.Context())
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Key error")
		return
	}
	writeJSON(w, http.StatusOK, s.jwksJSON(key))
}

// handlePrelogin returns the KDF parameters the client must use to derive
// the master key before attempting a login.
func (s *Service) handlePrelogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	kdf := bwcrypto.DefaultKDF()
	if account, err := s.accountByEmail(r.Context(), body.Email); err == nil && account.PasswordHash != "" {
		kdf = account.Kdf
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kdf":            kdf.Type,
		"kdfIterations":  kdf.Iterations,
		"kdfMemory":      nullInt(kdf.MemoryMB),
		"kdfParallelism": nullInt(kdf.Parallelism),
		"kdfSettings": map[string]any{
			"kdfType":     kdf.Type,
			"iterations":  kdf.Iterations,
			"memory":      nullInt(kdf.MemoryMB),
			"parallelism": nullInt(kdf.Parallelism),
		},
		"salt": nil,
	})
}

// handleConnectToken is the identity endpoint backing every client login:
// password grant, refresh grant and the two-factor retry round-trip.
func (s *Service) handleConnectToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeGrantError(w, http.StatusBadRequest, "Malformed request", nil)
		return
	}
	form := r.PostForm
	// Clients historically sent both snake_case and camelCase field names.
	get := func(key string) string {
		if v := form.Get(key); v != "" {
			return v
		}
		return form.Get(strings.ReplaceAll(key, "_", ""))
	}

	switch get("grant_type") {
	case "password":
		s.passwordGrant(w, r, get)
	case "refresh_token":
		s.refreshGrant(w, r, get)
	default:
		writeGrantError(w, http.StatusBadRequest, "Invalid type", nil)
	}
}

func (s *Service) passwordGrant(w http.ResponseWriter, r *http.Request, get func(string) string) {
	clientID := get("client_id")
	password := get("password")
	scope := get("scope")
	username := get("username")
	deviceID := get("device_identifier")
	deviceName := get("device_name")
	deviceTypeRaw := get("device_type")

	if clientID == "" || password == "" || scope == "" || username == "" {
		writeGrantError(w, http.StatusBadRequest, "Request missing parameters", nil)
		return
	}

	fail := func() {
		writeGrantError(w, http.StatusBadRequest, "Username or password is incorrect. Try again.", nil)
	}

	account, err := s.accountByEmail(r.Context(), username)
	if err != nil || account.Status != "active" || account.PasswordHash == "" || account.UserKey == "" {
		fail()
		return
	}
	if get("authrequest") != "" {
		// Login-with-passkey requests are not supported; the access code in
		// `password` is not a master key, so this attempt fails.
		fail()
		return
	}

	masterKey, err := decodeB64Key(password)
	if err != nil || !bwcrypto.VerifyMasterKey(masterKey, bwcrypto.NormalizeSalt(account.Email), account.PasswordHash) {
		fail()
		return
	}

	// Two-factor gate: only reached after the master password proved valid,
	// exactly like upstream. The device is registered first so a "remember
	// this device" token has somewhere to live on the very first login.
	if account.TwoFactorEnabled {
		device, err := s.upsertDevice(r.Context(), account.UserID, deviceID, deviceName, parseDeviceType(deviceTypeRaw))
		if err != nil {
			writeGrantError(w, http.StatusInternalServerError, "Device error", nil)
			return
		}
		valid, rememberToken, needsPrompt := s.checkTwoFactor(r.Context(), account, deviceID,
			get("two_factor_provider"), get("two_factor_token"), get("two_factor_remember"))
		if needsPrompt {
			writeGrantError(w, http.StatusBadRequest, "Two factor required.", map[string]any{
				"TwoFactorProviders":   []string{"0"},
				"TwoFactorProviders2":  map[string]any{"0": nil},
				"MasterPasswordPolicy": nil,
			})
			return
		}
		if !valid {
			writeGrantError(w, http.StatusBadRequest, "Two step token is invalid. Try again.", nil)
			return
		}
		s.respondToken(w, r, account, device, clientID, scope, rememberToken)
		return
	}

	device, err := s.upsertDevice(r.Context(), account.UserID, deviceID, deviceName, parseDeviceType(deviceTypeRaw))
	if err != nil {
		writeGrantError(w, http.StatusInternalServerError, "Device error", nil)
		return
	}

	s.respondToken(w, r, account, device, clientID, scope, "")
}

// respondToken issues the access/refresh token pair plus the key material a
// (re)logging-in client needs to unlock its vault locally.
func (s *Service) respondToken(w http.ResponseWriter, r *http.Request, account accountRecord, device deviceRecord, clientID, scope, twoFactorToken string) {
	key, err := s.loadOrCreateServiceKey(r.Context())
	if err != nil {
		writeGrantError(w, http.StatusInternalServerError, "Signing key error", nil)
		return
	}
	refreshToken, err := s.issueRefreshToken(r.Context(), device.ID)
	if err != nil {
		writeGrantError(w, http.StatusInternalServerError, "Token error", nil)
		return
	}
	now := time.Now().UTC()
	accessToken, err := s.signAccessToken(key, domainFromRequest(r, s.domainOverride),
		account.UserID, account.Email, account.displayName(), clientID, device, now, now.Add(jwtAccessTokenTTL))
	if err != nil {
		writeGrantError(w, http.StatusInternalServerError, "Token error", nil)
		return
	}

	response := map[string]any{
		"access_token":         accessToken,
		"expires_in":           int(jwtAccessTokenTTL.Seconds()),
		"token_type":           "Bearer",
		"refresh_token":        refreshToken,
		"scope":                scope,
		"Key":                  account.UserKey,
		"PrivateKey":           nullableText(account.PrivateKey),
		"Kdf":                  account.Kdf.Type,
		"KdfIterations":        account.Kdf.Iterations,
		"KdfMemory":            nullInt(account.Kdf.MemoryMB),
		"KdfParallelism":       nullInt(account.Kdf.Parallelism),
		"ForcePasswordReset":   false,
		"MasterPasswordPolicy": nil,
		"AccountKeys":          accountKeysJSON(account),
		"UserDecryptionOptions": map[string]any{
			"HasMasterPassword":    true,
			"MasterPasswordUnlock": masterPasswordUnlockJSON(account),
			"Object":               "userDecryptionOptions",
		},
	}
	if twoFactorToken != "" {
		response["TwoFactorToken"] = twoFactorToken
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) refreshGrant(w http.ResponseWriter, r *http.Request, get func(string) string) {
	token := get("refresh_token")
	if token == "" {
		writeGrantError(w, http.StatusBadRequest, "Missing refresh_token", nil)
		return
	}
	account, device, err := s.deviceByRefreshToken(r.Context(), token)
	if err != nil || account.Status != "active" {
		writeGrantError(w, http.StatusBadRequest, "Unable to refresh login credentials", nil)
		return
	}
	clientID := get("client_id")
	if clientID == "" {
		clientID = "unknown"
	}
	s.respondToken(w, r, account, device, clientID, "api offline_access", "")
}

// checkTwoFactor validates the second factor of a login attempt.
// needsPrompt is true when the client must ask the user for a code (missing
// or unknown provider); valid=false with needsPrompt=false means the supplied
// code was wrong. rememberToken is set when the client asked to be remembered
// and the code was accepted.
func (s *Service) checkTwoFactor(ctx context.Context, account accountRecord, deviceID, providerRaw, codeRaw, rememberRaw string) (valid bool, rememberToken string, needsPrompt bool) {
	codeRaw = strings.TrimSpace(codeRaw)
	provider, err := strconv.Atoi(strings.TrimSpace(providerRaw))
	if err != nil {
		provider = 0
	}

	device, deviceErr := s.deviceByID(ctx, account.UserID, deviceID)

	switch {
	case provider == twoFactorProviderRemember:
		if deviceErr != nil || device.TwoFactorRemember == "" || codeRaw == "" {
			return false, "", true
		}
		if secureCompare(device.TwoFactorRemember, codeRaw) {
			return true, "", false
		}
		// Stale remember token: fall back to prompting for a fresh code.
		return false, "", true
	case provider == 0:
		if codeRaw == "" {
			return false, "", true
		}
		if !account.TwoFactorSecret.Valid || account.TwoFactorSecret.String == "" {
			return false, "", true
		}
		if !ValidateTOTP(account.TwoFactorSecret.String, codeRaw, time.Now().UTC()) {
			return false, "", false
		}
	default:
		return false, "", true
	}

	if rememberRaw == "1" && deviceErr == nil && device.ID != "" {
		token := randomToken(32)
		if _, err := s.db.ExecContext(ctx,
			`UPDATE bitwarden_devices SET twofactor_remember = $1 WHERE id = $2`, token, device.ID); err == nil {
			rememberToken = token
		}
	}
	return true, rememberToken, false
}

func parseDeviceType(raw string) int {
	if raw == "" {
		return 14 // unknown browser, like upstream
	}
	if value, err := strconv.Atoi(raw); err == nil {
		return value
	}
	// Some clients send the platform name instead of a number.
	switch strings.ToLower(raw) {
	case "ios":
		return 8
	case "android":
		return 7
	}
	return 14
}

func nullableText(value sql.NullString) any {
	if !value.Valid || value.String == "" {
		return nil
	}
	return value.String
}

func accountKeysJSON(account accountRecord) any {
	if account.PrivateKey.Valid && account.PrivateKey.String != "" {
		return map[string]any{
			"publicKeyEncryptionKeyPair": map[string]any{
				"wrappedPrivateKey": account.PrivateKey.String,
				"publicKey":         nullableText(account.PublicKey),
				"Object":            "publicKeyEncryptionKeyPair",
			},
			"Object": "privateKeys",
		}
	}
	return nil
}

func masterPasswordUnlockJSON(account accountRecord) map[string]any {
	return map[string]any{
		"Kdf": map[string]any{
			"KdfType":     account.Kdf.Type,
			"Iterations":  account.Kdf.Iterations,
			"Memory":      nullInt(account.Kdf.MemoryMB),
			"Parallelism": nullInt(account.Kdf.Parallelism),
		},
		"MasterKeyEncryptedUserKey": account.UserKey,
		"MasterKeyWrappedUserKey":   account.UserKey,
		"Salt":                      bwcrypto.NormalizeSalt(account.Email),
	}
}
