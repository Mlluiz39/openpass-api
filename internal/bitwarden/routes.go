package bitwarden

import "net/http"

// RegisterRoutes mounts the Bitwarden-compatible API on the shared mux:
// the /identity namespace (login, token, JWKS) plus the /api namespace
// (sync, ciphers, folders, accounts, settings, devices). Every /api route
// goes through requireAuth (Bearer JWT), except the few public ones.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	auth := s.requireAuth
	authenticated := func(handler http.HandlerFunc) http.Handler {
		return auth(handler)
	}

	// ---- identity ----
	mux.HandleFunc("GET /identity/.well-known/openid-configuration", s.handleOpenIDConfiguration)
	mux.HandleFunc("GET /identity/keys", s.handleKeys)
	mux.HandleFunc("POST /identity/connect/token", s.handleConnectToken)
	mux.HandleFunc("POST /identity/accounts/prelogin", s.handlePrelogin)
	mux.HandleFunc("POST /identity/accounts/prelogin/password", s.handlePrelogin)

	// ---- public api ----
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /api/alive", s.handleAlive)
	mux.HandleFunc("GET /api/now", s.handleNow)
	mux.HandleFunc("GET /api/version", s.handleVersion)
	mux.HandleFunc("GET /api/devices/knowndevice", s.handleKnownDevice)
	mux.HandleFunc("POST /api/accounts/password-hint", s.handlePasswordHint)

	// ---- sync ----
	mux.Handle("GET /api/sync", authenticated(s.handleSync))

	// ---- ciphers ----
	mux.Handle("GET /api/ciphers", authenticated(s.handleListCiphers))
	mux.Handle("GET /api/ciphers/"+totpCollectionID, authenticated(s.handleListTOTPCiphers))
	mux.Handle("POST /api/ciphers", authenticated(s.handleCreateCipher))
	mux.Handle("GET /api/ciphers/{id}", authenticated(s.handleGetCipher))
	mux.Handle("PUT /api/ciphers/{id}", authenticated(s.handleUpdateCipher))
	mux.Handle("POST /api/ciphers/{id}", authenticated(s.handleUpdateCipher))
	mux.Handle("PUT /api/ciphers/{id}/favorite", authenticated(s.handleFavoriteCipher))
	mux.Handle("POST /api/ciphers/{id}/favorite", authenticated(s.handleFavoriteCipher))
	mux.Handle("PUT /api/ciphers/{id}/partial", authenticated(s.handleCipherPartial))
	mux.Handle("POST /api/ciphers/{id}/partial", authenticated(s.handleCipherPartial))
	mux.Handle("POST /api/ciphers/{id}/delete", authenticated(s.handleTrashCipher))
	mux.Handle("PUT /api/ciphers/{id}/delete", authenticated(s.handleTrashCipher))
	mux.Handle("DELETE /api/ciphers/{id}", authenticated(s.handleDeleteCipher))
	mux.Handle("POST /api/ciphers/{id}/restore", authenticated(s.handleRestoreCipher))
	mux.Handle("PUT /api/ciphers/{id}/restore", authenticated(s.handleRestoreCipher))
	mux.Handle("DELETE /api/ciphers", authenticated(s.handleBulkDeleteCiphers))
	mux.Handle("POST /api/ciphers/delete", authenticated(s.handleBulkDeleteCiphers))
	mux.Handle("PUT /api/ciphers/delete", authenticated(s.handleBulkDeleteCiphers))
	mux.Handle("POST /api/ciphers/restore", authenticated(s.handleBulkRestoreCiphers))
	mux.Handle("PUT /api/ciphers/restore", authenticated(s.handleBulkRestoreCiphers))
	mux.Handle("POST /api/ciphers/import", authenticated(s.handleImportCiphers))
	mux.Handle("POST /api/trash/empty", authenticated(s.handleEmptyTrash))

	// ---- folders ----
	mux.Handle("GET /api/folders", authenticated(s.handleListFolders))
	mux.Handle("POST /api/folders", authenticated(s.handleCreateFolder))
	mux.Handle("GET /api/folders/{id}", authenticated(s.handleGetFolder))
	mux.Handle("PUT /api/folders/{id}", authenticated(s.handleUpdateFolder))
	mux.Handle("POST /api/folders/{id}", authenticated(s.handleUpdateFolder))
	mux.Handle("DELETE /api/folders/{id}", authenticated(s.handleDeleteFolder))
	mux.Handle("POST /api/folders/{id}/delete", authenticated(s.handleDeleteFolder))

	// ---- accounts ----
	mux.Handle("GET /api/accounts/profile", authenticated(s.handleProfile))
	mux.Handle("PUT /api/accounts/profile", authenticated(s.handleUpdateProfile))
	mux.Handle("POST /api/accounts/profile", authenticated(s.handleUpdateProfile))
	mux.Handle("GET /api/accounts/keys", authenticated(s.handleGetKeys))
	mux.Handle("POST /api/accounts/keys", authenticated(s.handlePostKeys))
	mux.Handle("POST /api/accounts/password", authenticated(s.handleChangeMasterPassword))
	mux.Handle("POST /api/accounts/verify-password", authenticated(s.handleVerifyPassword))
	mux.Handle("GET /api/accounts/revision-date", authenticated(s.handleRevisionDate))
	mux.Handle("POST /api/accounts/security-stamp", authenticated(s.handleSecurityStamp))
	mux.Handle("GET /api/users/{id}/public-key", authenticated(s.handlePublicKey))

	// ---- settings ----
	mux.Handle("GET /api/settings/domains", authenticated(s.handleGetDomains))
	mux.Handle("POST /api/settings/domains", authenticated(s.handleSetDomains))
	mux.Handle("PUT /api/settings/domains", authenticated(s.handleSetDomains))
	mux.Handle("GET /api/settings/two-factor", authenticated(s.handleTwoFactorStatus))
	mux.Handle("POST /api/settings/two-factor/authenticator", authenticated(s.handleEnableAuthenticator))
	mux.Handle("POST /api/settings/two-factor/authenticator/confirm", authenticated(s.handleConfirmAuthenticator))
	mux.Handle("POST /api/settings/two-factor/disable", authenticated(s.handleDisableTwoFactor))

	// ---- devices ----
	mux.Handle("GET /api/devices", authenticated(s.handleListDevices))
	mux.Handle("GET /api/devices/identifier/{identifier}", authenticated(s.handleGetDevice))
	mux.Handle("POST /api/devices/identifier/{identifier}/token", authenticated(s.handleDeviceToken))
	mux.Handle("PUT /api/devices/identifier/{identifier}/token", authenticated(s.handleDeviceToken))

	// ---- misc ----
	mux.Handle("GET /api/hibp/breach", authenticated(s.handleBreach))
}
