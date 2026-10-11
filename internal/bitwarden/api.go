package bitwarden

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openpass/api/internal/bitwarden/bwcrypto"
)

// Sentinel errors mapped to client-facing messages by the handlers.
var (
	errInvalidType   = errors.New("Invalid type")
	errInvalidFolder = errors.New("Invalid folder")
)

func nullString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	out := value.String
	return &out
}

// totpCollectionID is the sentinel "cipher id" clients use to fetch every
// cipher that carries a TOTP field (upstream convention).
const totpCollectionID = "3lzaazFjuUJ6LbiC"

// ---- public/meta ----

func (s *Service) handleConfig(w http.ResponseWriter, r *http.Request) {
	domain := domainFromRequest(r, s.domainOverride)
	writeJSON(w, http.StatusOK, map[string]any{
		"version": serverVersion,
		"gitHash": nil,
		"server":  map[string]any{"name": "OpenPass", "url": "https://github.com/openpass/api"},
		"settings": map[string]any{
			// OpenPass is invite-only: signal clients that self-registration
			// is off so they hide the sign-up flows.
			"disableUserRegistration":         true,
			"suppressOnboardingInterstitials": true,
		},
		"environment": map[string]any{
			"vault":         domain,
			"api":           domain + "/api",
			"identity":      domain + "/identity",
			"notifications": "",
			"sso":           "",
			"cloudRegion":   nil,
		},
		"push":          map[string]any{"pushTechnology": 0, "vapidPublicKey": nil},
		"featureStates": map[string]any{},
		"communication": nil,
		"object":        "config",
	})
}

func (s *Service) handleAlive(w http.ResponseWriter, r *http.Request) {
	if err := s.db.PingContext(r.Context()); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, nowBitwarden())
}

func (s *Service) handleNow(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, nowBitwarden())
}

func (s *Service) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, serverVersion)
}

// ---- profile helpers ----

func (s *Service) profileJSON(account accountRecord) map[string]any {
	return map[string]any{
		"_status":                 0,
		"accountKeys":             accountKeysJSON(account),
		"id":                      account.UserID,
		"name":                    account.displayName(),
		"email":                   account.Email,
		"emailVerified":           true,
		"premium":                 true,
		"premiumFromOrganization": false,
		"culture":                 "en-US",
		"twoFactorEnabled":        account.TwoFactorEnabled,
		"key":                     account.UserKey,
		"privateKey":              nullableText(account.PrivateKey),
		"securityStamp":           account.SecurityStamp,
		"organizations":           []any{},
		"organizationsNew":        []any{},
		"providers":               []any{},
		"providerOrganizations":   []any{},
		"forcePasswordReset":      false,
		"avatarColor":             nullableText(account.AvatarColor),
		"usesKeyConnector":        false,
		"creationDate":            account.CreatedAt,
		"object":                  "profile",
	}
}

// ---- sync ----

func (s *Service) handleSync(w http.ResponseWriter, r *http.Request) {
	account, ok := FromContext(r.Context())
	if !ok {
		writeMessage(w, http.StatusUnauthorized, "Not authorized.")
		return
	}
	folders, err := s.listFolders(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load folders")
		return
	}
	ciphers, err := s.listCiphers(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load ciphers")
		return
	}

	foldersJSON := make([]any, 0, len(folders))
	for _, folder := range folders {
		foldersJSON = append(foldersJSON, folderJSON(folder))
	}
	ciphersJSON := make([]any, 0, len(ciphers))
	for _, cipher := range ciphers {
		ciphersJSON = append(ciphersJSON, cipherJSON(cipher))
	}

	excludeDomains := r.URL.Query().Get("excludeDomains") == "true"
	var domains any
	if excludeDomains {
		domains = nil
	} else {
		domains = map[string]any{
			"equivalentDomains":       parseJSONList(account.EquivalentDomains),
			"globalEquivalentDomains": []any{},
			"object":                  "domains",
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"profile":     s.profileJSON(account),
		"folders":     foldersJSON,
		"collections": []any{},
		"policies":    []any{},
		"policiesNew": []any{},
		"ciphers":     ciphersJSON,
		"domains":     domains,
		"sends":       []any{},
		"userDecryption": map[string]any{
			"masterPasswordUnlock": masterPasswordUnlockJSON(account),
			"userKeyId":            nil,
		},
		"object": "sync",
	})
}

// ---- ciphers ----

type cipherRequest struct {
	ID                    *string         `json:"id"`
	FolderID              *string         `json:"folderId"`
	OrganizationID        *string         `json:"organizationId"`
	Type                  int             `json:"type"`
	Name                  string          `json:"name"`
	Notes                 *string         `json:"notes"`
	Favorite              *bool           `json:"favorite"`
	Reprompt              *int            `json:"reprompt"`
	Key                   *string         `json:"key"`
	Login                 json.RawMessage `json:"login"`
	SecureNote            json.RawMessage `json:"secureNote"`
	Card                  json.RawMessage `json:"card"`
	Identity              json.RawMessage `json:"identity"`
	Fields                json.RawMessage `json:"fields"`
	PasswordHistory       json.RawMessage `json:"passwordHistory"`
	LastKnownRevisionDate *string         `json:"lastKnownRevisionDate"`
}

// typeData returns the encrypted sub-object matching the cipher type, with
// the client-only `response` keys stripped (upstream does the same before
// persisting).
func (req cipherRequest) typeData() (string, bool) {
	var raw json.RawMessage
	switch req.Type {
	case 1:
		raw = req.Login
	case 2:
		raw = req.SecureNote
	case 3:
		raw = req.Card
	case 4:
		raw = req.Identity
	default:
		return "", false
	}
	if len(raw) == 0 || string(raw) == "null" {
		// Secure notes may omit the sub-object entirely.
		if req.Type == 2 {
			return `{"type":0}`, true
		}
		return "", false
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	value = stripResponseKeys(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func stripResponseKeys(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		delete(typed, "response")
		delete(typed, "Response")
		for key, item := range typed {
			typed[key] = stripResponseKeys(item)
		}
		return typed
	case []any:
		for i, item := range typed {
			typed[i] = stripResponseKeys(item)
		}
		return typed
	default:
		return value
	}
}

func optionalJSON(raw json.RawMessage) *string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	value := stripResponseKeys(mustUnmarshal(raw))
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	out := string(encoded)
	return &out
}

func mustUnmarshal(raw json.RawMessage) any {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return value
}

func parseJSONList(raw string) []any {
	if strings.TrimSpace(raw) == "" {
		return []any{}
	}
	var out []any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []any{}
	}
	return out
}

// cipherJSON renders a stored cipher in the `cipherDetails` response shape,
// including the backwards-compat conveniences (first URI at the top level,
// normalized `match` values, secure-note type default).
func cipherJSON(c cipherRecord) map[string]any {
	typeData := map[string]any{}
	if strings.TrimSpace(c.Data) != "" {
		_ = json.Unmarshal([]byte(c.Data), &typeData)
	}

	var key string
	switch c.Type {
	case 1:
		key = "login"
		// Upstream always sends a top-level `uri`; mobile clients read it.
		typeData["uri"] = nil
		if uris, ok := typeData["uris"].([]any); ok && len(uris) > 0 {
			if first, ok := uris[0].(map[string]any); ok {
				typeData["uri"] = first["uri"]
			}
			for _, entry := range uris {
				if uri, ok := entry.(map[string]any); ok {
					if asString, ok := uri["match"].(string); ok {
						if value, err := strconv.Atoi(asString); err == nil {
							uri["match"] = value
						} else {
							uri["match"] = nil
						}
					}
				}
			}
		}
	case 2:
		key = "secureNote"
		if _, ok := typeData["type"]; !ok {
			typeData["type"] = 0
		}
	case 3:
		key = "card"
	case 4:
		key = "identity"
	default:
		key = "login"
	}

	var deleted any
	if c.DeletedAt.Valid && c.DeletedAt.String != "" {
		deleted = c.DeletedAt.String
	}
	var fields []any
	if c.Fields.Valid && strings.TrimSpace(c.Fields.String) != "" {
		_ = json.Unmarshal([]byte(c.Fields.String), &fields)
	}
	if fields == nil {
		fields = []any{}
	}
	var history []any
	if c.PasswordHistory.Valid && strings.TrimSpace(c.PasswordHistory.String) != "" {
		_ = json.Unmarshal([]byte(c.PasswordHistory.String), &history)
	}
	if history == nil {
		history = []any{}
	}
	var folderID any
	if c.FolderID.Valid {
		folderID = c.FolderID.String
	}

	response := map[string]any{
		"object":              "cipherDetails",
		"id":                  c.ID,
		"organizationId":      nil,
		"folderId":            folderID,
		"type":                c.Type,
		"key":                 nullableText(c.Key),
		"name":                c.Name,
		"notes":               nullableText(c.Notes),
		"favorite":            c.Favorite,
		"reprompt":            c.Reprompt,
		"fields":              fields,
		"passwordHistory":     history,
		"collectionIds":       []any{},
		"attachments":         nil,
		"organizationUseTotp": true,
		"creationDate":        c.CreatedAt,
		"revisionDate":        c.UpdatedAt,
		"deletedDate":         deleted,
		"archivedDate":        nil,
		"edit":                true,
		"viewPassword":        true,
		"permissions":         map[string]any{"delete": true, "restore": true},
		"login":               nil,
		"secureNote":          nil,
		"card":                nil,
		"identity":            nil,
	}
	response[key] = typeData
	return response
}

func folderJSON(f folderRecord) map[string]any {
	return map[string]any{
		"object":       "folder",
		"id":           f.ID,
		"name":         f.Name,
		"revisionDate": f.UpdatedAt,
	}
}

func (s *Service) handleListCiphers(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	ciphers, err := s.listCiphers(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load ciphers")
		return
	}
	data := make([]any, 0, len(ciphers))
	for _, cipher := range ciphers {
		data = append(data, cipherJSON(cipher))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "object": "list", "continuationToken": nil})
}

// handleListTOTPCiphers implements the sentinel-id endpoint: clients request
// `/api/ciphers/3lzaazFjuUJ6LbiC` to get every cipher holding a TOTP seed.
func (s *Service) handleListTOTPCiphers(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	ciphers, err := s.listCiphers(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load ciphers")
		return
	}
	data := []any{}
	for _, cipher := range ciphers {
		if cipher.Type != 1 || cipher.DeletedAt.Valid {
			continue
		}
		var login map[string]any
		if err := json.Unmarshal([]byte(cipher.Data), &login); err != nil {
			continue
		}
		if totp, ok := login["totp"].(string); ok && totp != "" {
			data = append(data, cipherJSON(cipher))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "object": "list", "continuationToken": nil})
}

func (s *Service) handleGetCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	cipher, err := s.cipherByID(r.Context(), account.UserID, r.PathValue("id"))
	if err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

func (s *Service) handleCreateCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req cipherRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	cipher, err := s.createCipherFromRequest(r, *account, req)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

func (s *Service) createCipherFromRequest(r *http.Request, account accountRecord, req cipherRequest) (cipherRecord, error) {
	data, ok := req.typeData()
	if !ok {
		return cipherRecord{}, errInvalidType
	}
	if req.FolderID != nil && *req.FolderID != "" {
		if _, err := s.folderByID(r.Context(), account.UserID, *req.FolderID); err != nil {
			return cipherRecord{}, errInvalidFolder
		}
	}
	return s.createCipher(r.Context(), account.UserID, cipherInput{
		FolderID:        req.FolderID,
		Type:            req.Type,
		Name:            req.Name,
		Notes:           req.Notes,
		Data:            data,
		Key:             req.Key,
		Fields:          optionalJSON(req.Fields),
		PasswordHistory: optionalJSON(req.PasswordHistory),
		Favorite:        req.Favorite,
		Reprompt:        req.Reprompt,
	})
}

func (s *Service) handleUpdateCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	id := r.PathValue("id")
	existing, err := s.cipherByID(r.Context(), account.UserID, id)
	if err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	var req cipherRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	// Reject stale writes: the client's copy must match what the server has.
	if req.LastKnownRevisionDate != nil && strings.TrimSpace(*req.LastKnownRevisionDate) != "" {
		if clientTime, err := parseBitwardenTime(*req.LastKnownRevisionDate); err == nil {
			if stored, err := parseBitwardenTime(existing.UpdatedAt); err == nil && stored.After(clientTime.Add(time.Second)) {
				writeMessage(w, http.StatusBadRequest, "The client copy of this cipher is out of date. Resync the client and try again.")
				return
			}
		}
	}
	data, ok := req.typeData()
	if !ok {
		writeMessage(w, http.StatusBadRequest, "Data missing")
		return
	}
	if req.FolderID != nil && *req.FolderID != "" {
		if _, err := s.folderByID(r.Context(), account.UserID, *req.FolderID); err != nil {
			writeMessage(w, http.StatusBadRequest, "Invalid folder")
			return
		}
	}
	cipher, err := s.updateCipher(r.Context(), account.UserID, id, cipherInput{
		FolderID:        req.FolderID,
		Type:            req.Type,
		Name:            req.Name,
		Notes:           req.Notes,
		Data:            data,
		Key:             req.Key,
		Fields:          optionalJSON(req.Fields),
		PasswordHistory: optionalJSON(req.PasswordHistory),
		Favorite:        req.Favorite,
		Reprompt:        req.Reprompt,
	})
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Unable to update cipher")
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

func (s *Service) handleCipherPartial(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		FolderID *string `json:"folderId"`
		Favorite bool    `json:"favorite"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	id := r.PathValue("id")
	existing, err := s.cipherByID(r.Context(), account.UserID, id)
	if err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	folderID := req.FolderID
	if folderID != nil && *folderID != "" {
		if _, err := s.folderByID(r.Context(), account.UserID, *folderID); err != nil {
			writeMessage(w, http.StatusBadRequest, "Invalid folder")
			return
		}
	}
	// Partial updates only rewrite the per-user properties; the encrypted
	// payload itself is untouched.
	cipher, err := s.updateCipher(r.Context(), account.UserID, id, cipherInput{
		FolderID:        folderID,
		Type:            existing.Type,
		Name:            existing.Name,
		Notes:           nullString(existing.Notes),
		Data:            existing.Data,
		Key:             nullString(existing.Key),
		Fields:          nullString(existing.Fields),
		PasswordHistory: nullString(existing.PasswordHistory),
		Favorite:        &req.Favorite,
		Reprompt:        &existing.Reprompt,
	})
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Unable to update cipher")
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

func (s *Service) handleFavoriteCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		Favorite bool `json:"favorite"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	cipher, err := s.setCipherFavorite(r.Context(), account.UserID, r.PathValue("id"), req.Favorite)
	if err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

// handleTrashCipher moves a cipher to the trash (POST/PUT .../delete).
func (s *Service) handleTrashCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if _, err := s.setCipherDeleted(r.Context(), account.UserID, r.PathValue("id"), true); err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleRestoreCipher moves a cipher out of the trash.
func (s *Service) handleRestoreCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.restoreCiphers(r.Context(), account.UserID, []string{r.PathValue("id")}); err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	cipher, err := s.cipherByID(r.Context(), account.UserID, r.PathValue("id"))
	if err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, cipherJSON(cipher))
}

// handleDeleteCipher permanently removes one cipher (trash → delete forever).
func (s *Service) handleDeleteCipher(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.deleteCipher(r.Context(), account.UserID, r.PathValue("id")); err != nil {
		writeMessage(w, http.StatusNotFound, "Cipher doesn't exist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Service) handleBulkDeleteCiphers(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.deleteCiphers(r.Context(), account.UserID, idsFromRequest(r)); err != nil {
		writeMessage(w, http.StatusBadRequest, "Unable to delete ciphers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Service) handleBulkRestoreCiphers(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.restoreCiphers(r.Context(), account.UserID, idsFromRequest(r)); err != nil {
		writeMessage(w, http.StatusBadRequest, "Unable to restore ciphers")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Service) handleEmptyTrash(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.emptyTrash(r.Context(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to empty trash")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// handleImportCiphers implements the bulk import the web vault uses.
func (s *Service) handleImportCiphers(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		Ciphers []cipherRequest `json:"ciphers"`
		Folders []struct {
			ID   *string `json:"id"`
			Name string  `json:"name"`
		} `json:"folders"`
		FolderRelationships []struct {
			Key   int `json:"key"`
			Value int `json:"value"`
		} `json:"folderRelationships"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}

	folderIDs := make([]string, 0, len(req.Folders))
	for _, folder := range req.Folders {
		if folder.ID != nil && *folder.ID != "" {
			if existing, err := s.folderByID(r.Context(), account.UserID, *folder.ID); err == nil {
				folderIDs = append(folderIDs, existing.ID)
				continue
			}
		}
		created, err := s.createFolder(r.Context(), account.UserID, folder.Name)
		if err != nil {
			writeMessage(w, http.StatusBadRequest, "Unable to create folder")
			return
		}
		folderIDs = append(folderIDs, created.ID)
	}

	folderFor := map[int]string{}
	for _, relation := range req.FolderRelationships {
		if relation.Value >= 0 && relation.Value < len(folderIDs) {
			folderFor[relation.Key] = folderIDs[relation.Value]
		}
	}

	for index, cipherReq := range req.Ciphers {
		if folderID, ok := folderFor[index]; ok {
			cipherReq.FolderID = &folderID
		}
		if _, err := s.createCipherFromRequest(r, *account, cipherReq); err != nil {
			writeMessage(w, http.StatusBadRequest, "The model state is invalid.")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// ---- folders ----

func (s *Service) handleListFolders(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	folders, err := s.listFolders(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load folders")
		return
	}
	data := make([]any, 0, len(folders))
	for _, folder := range folders {
		data = append(data, folderJSON(folder))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "object": "list", "continuationToken": nil})
}

func (s *Service) handleGetFolder(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	folder, err := s.folderByID(r.Context(), account.UserID, r.PathValue("id"))
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Folder does not exist or belongs to another user")
		return
	}
	writeJSON(w, http.StatusOK, folderJSON(folder))
}

type folderRequest struct {
	Name string  `json:"name"`
	ID   *string `json:"id"`
}

func (s *Service) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req folderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	folder, err := s.createFolder(r.Context(), account.UserID, req.Name)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Unable to create folder")
		return
	}
	writeJSON(w, http.StatusOK, folderJSON(folder))
}

func (s *Service) handleUpdateFolder(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req folderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	folder, err := s.updateFolder(r.Context(), account.UserID, r.PathValue("id"), req.Name)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Folder does not exist or belongs to another user")
		return
	}
	writeJSON(w, http.StatusOK, folderJSON(folder))
}

func (s *Service) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if err := s.deleteFolder(r.Context(), account.UserID, r.PathValue("id")); err != nil {
		writeMessage(w, http.StatusBadRequest, "Folder does not exist or belongs to another user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// ---- accounts ----

func (s *Service) handleProfile(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	writeJSON(w, http.StatusOK, s.profileJSON(*account))
}

func (s *Service) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if len(req.Name) > 50 {
		writeMessage(w, http.StatusBadRequest, "The field Name must be a string with a maximum length of 50.")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE users SET display_name = $1, updated_at = $2 WHERE id = $3`,
		req.Name, time.Now().UTC().Format(time.RFC3339), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to update profile")
		return
	}
	updated, err := s.accountByID(r.Context(), account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to update profile")
		return
	}
	writeJSON(w, http.StatusOK, s.profileJSON(updated))
}

func (s *Service) handleGetKeys(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if account.PrivateKey.Valid && account.PrivateKey.String != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"key":         account.UserKey,
			"publicKey":   nullableText(account.PublicKey),
			"privateKey":  account.PrivateKey.String,
			"accountKeys": accountKeysJSON(*account),
			"object":      "keys",
		})
		return
	}
	writeMessage(w, http.StatusNotFound, "User has no key pair")
}

func (s *Service) handlePostKeys(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	if account.PrivateKey.Valid && account.PrivateKey.String != "" {
		writeMessage(w, http.StatusBadRequest, "User has existing keypair")
		return
	}
	var req struct {
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
		PublicKey           string `json:"publicKey"`
	}
	if err := decodeJSON(r, &req); err != nil || req.EncryptedPrivateKey == "" || req.PublicKey == "" {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_accounts SET private_key = $1, public_key = $2, updated_at = $3 WHERE user_id = $4`,
		req.EncryptedPrivateKey, req.PublicKey, nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to store keys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"privateKey": req.EncryptedPrivateKey,
		"publicKey":  req.PublicKey,
		"object":     "keys",
	})
}

// changePasswordData accepts both the legacy and the current (wrapped)
// request shapes upstream clients send.
type changePasswordData struct {
	MasterPasswordHash    string  `json:"masterPasswordHash"`
	MasterPasswordHint    *string `json:"masterPasswordHint"`
	NewMasterPasswordHash string  `json:"newMasterPasswordHash"`
	Key                   string  `json:"key"`
	AuthenticationData    *struct {
		Salt                             string     `json:"salt"`
		Kdf                              kdfRequest `json:"kdf"`
		MasterPasswordAuthenticationHash string     `json:"masterPasswordAuthenticationHash"`
	} `json:"authenticationData"`
	UnlockData *struct {
		Salt                    string     `json:"salt"`
		Kdf                     kdfRequest `json:"kdf"`
		MasterKeyWrappedUserKey string     `json:"masterKeyWrappedUserKey"`
	} `json:"unlockData"`
}

type kdfRequest struct {
	Kdf            int `json:"kdf"`
	KdfType        int `json:"kdfType"`
	Iterations     int `json:"iterations"`
	KdfIterations  int `json:"kdfIterations"`
	Memory         int `json:"memory"`
	KdfMemory      int `json:"kdfMemory"`
	Parallelism    int `json:"parallelism"`
	KdfParallelism int `json:"kdfParallelism"`
}

func (k kdfRequest) params() bwcrypto.KdfParams {
	kdfType := k.Kdf
	if kdfType == 0 {
		kdfType = k.KdfType
	}
	iterations := k.Iterations
	if iterations == 0 {
		iterations = k.KdfIterations
	}
	memory := k.Memory
	if memory == 0 {
		memory = k.KdfMemory
	}
	parallelism := k.Parallelism
	if parallelism == 0 {
		parallelism = k.KdfParallelism
	}
	return bwcrypto.KdfParams{Type: kdfType, Iterations: iterations, MemoryMB: memory, Parallelism: parallelism}
}

func (s *Service) handleChangeMasterPassword(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req changePasswordData
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !verifyProvidedMasterHash(*account, req.MasterPasswordHash) {
		writeMessage(w, http.StatusBadRequest, "Invalid password")
		return
	}

	newHash, newKey := req.NewMasterPasswordHash, req.Key
	if req.AuthenticationData != nil && req.UnlockData != nil {
		newHash = req.AuthenticationData.MasterPasswordAuthenticationHash
		newKey = req.UnlockData.MasterKeyWrappedUserKey
	}
	if newHash == "" || newKey == "" {
		writeMessage(w, http.StatusBadRequest, "Invalid request!")
		return
	}

	hint := ""
	if req.MasterPasswordHint != nil {
		hint = strings.TrimSpace(*req.MasterPasswordHint)
	}
	stamp := randomUUID()
	if _, err := s.db.ExecContext(r.Context(), `UPDATE bitwarden_accounts SET
		password_hash = $1, user_key = $2, master_password_hint = $3, security_stamp = $4, updated_at = $5
		WHERE user_id = $6`,
		newHash, newKey, nullableString(&hint), stamp, nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to change password")
		return
	}
	// Every refresh token dies with the security stamp; the requesting
	// client keeps working until its access token expires.
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_devices SET refresh_token_hash = NULL WHERE user_id = $1`, account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to change password")
		return
	}
	_ = s.touchRevision(r.Context(), account.UserID)
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Service) handleVerifyPassword(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		MasterPasswordHash string `json:"masterPasswordHash"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !verifyProvidedMasterHash(*account, req.MasterPasswordHash) {
		writeMessage(w, http.StatusBadRequest, "Invalid password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// verifyProvidedMasterHash checks the client-sent master key hash against
// the stored one. Clients derive it as PBKDF2(masterKey, email, 1), which is
// exactly what provisioning stores, so a plain (constant-time) comparison of
// the decoded hashes is the correct check.
func verifyProvidedMasterHash(account accountRecord, provided string) bool {
	provided = strings.TrimSpace(provided)
	if provided == "" || account.PasswordHash == "" {
		return false
	}
	given, err := base64.StdEncoding.DecodeString(provided)
	if err != nil {
		return false
	}
	stored, err := base64.StdEncoding.DecodeString(account.PasswordHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(given, stored) == 1
}

func (s *Service) handleRevisionDate(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	updated, err := time.Parse(time.RFC3339, account.UpdatedAt)
	if err != nil {
		updated = time.Now().UTC()
	}
	writeJSON(w, http.StatusOK, updated.UnixMilli())
}

func (s *Service) handlePasswordHint(w http.ResponseWriter, r *http.Request) {
	// Password hints would leak account information without an e-mail
	// channel; this server never returns them.
	writeMessage(w, http.StatusBadRequest, "This server is not configured to provide password hints.")
}

func (s *Service) handleSecurityStamp(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		MasterPasswordHash string `json:"masterPasswordHash"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !verifyProvidedMasterHash(*account, req.MasterPasswordHash) {
		writeMessage(w, http.StatusBadRequest, "Invalid password")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_accounts SET security_stamp = $1, updated_at = $2 WHERE user_id = $3`,
		randomUUID(), nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to reset security stamp")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`DELETE FROM bitwarden_devices WHERE user_id = $1`, account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to reset security stamp")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Service) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	var publicKey string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT b.public_key FROM bitwarden_accounts b JOIN users u ON u.id = b.user_id WHERE u.id = $1`,
		r.PathValue("id")).Scan(&publicKey)
	if err != nil || publicKey == "" {
		writeMessage(w, http.StatusNotFound, "User has no public_key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"userId":    r.PathValue("id"),
		"publicKey": publicKey,
		"object":    "userKey",
	})
}

// ---- settings ----

func (s *Service) handleGetDomains(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"equivalentDomains":       parseJSONList(account.EquivalentDomains),
		"globalEquivalentDomains": []any{},
		"object":                  "domains",
	})
}

func (s *Service) handleSetDomains(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		ExcludedGlobalEquivalentDomains []int      `json:"excludedGlobalEquivalentDomains"`
		EquivalentDomains               [][]string `json:"equivalentDomains"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	equivalent, err := json.Marshal(req.EquivalentDomains)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	excluded, err := json.Marshal(req.ExcludedGlobalEquivalentDomains)
	if err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_accounts SET equivalent_domains = $1, excluded_globals = $2, updated_at = $3 WHERE user_id = $4`,
		string(equivalent), string(excluded), nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to save domains")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// ---- two-factor management ----

func (s *Service) handleTwoFactorStatus(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": []any{map[string]any{
			"Method":  0,
			"Enabled": account.TwoFactorEnabled,
			"Object":  "twoFactorProvider",
		}},
		"object": "list",
	})
}

func (s *Service) handleEnableAuthenticator(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		MasterPasswordHash string `json:"masterPasswordHash"`
	}
	_ = decodeJSON(r, &req)
	if req.MasterPasswordHash != "" && !verifyProvidedMasterHash(*account, req.MasterPasswordHash) {
		writeMessage(w, http.StatusBadRequest, "Invalid password")
		return
	}

	secret := account.TwoFactorSecret.String
	if secret == "" {
		generated, err := GenerateTOTPSeed()
		if err != nil {
			writeMessage(w, http.StatusInternalServerError, "Unable to generate secret")
			return
		}
		secret = generated
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE bitwarden_accounts SET two_factor_secret = $1, updated_at = $2 WHERE user_id = $3`,
			secret, nowBitwarden(), account.UserID); err != nil {
			writeMessage(w, http.StatusInternalServerError, "Unable to store secret")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"Enabled": false,
		"Secret":  secret,
		"Code":    "",
		"Method":  0,
		"Object":  "twoFactorAuthenticator",
	})
}

func (s *Service) handleConfirmAuthenticator(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !account.TwoFactorSecret.Valid || account.TwoFactorSecret.String == "" {
		writeMessage(w, http.StatusBadRequest, "Two factor doesn't exist")
		return
	}
	if !ValidateTOTP(account.TwoFactorSecret.String, req.Code, time.Now().UTC()) {
		writeMessage(w, http.StatusBadRequest, "Two-step token is invalid. Try again.")
		return
	}
	if _, err := s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_accounts SET two_factor_enabled = 1, updated_at = $1 WHERE user_id = $2`,
		nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to enable two-factor")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"Enabled": true,
		"Object":  "twoFactorAuthenticator",
		"Method":  0,
	})
}

func (s *Service) handleDisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		MasterPasswordHash string `json:"masterPasswordHash"`
		Code               string `json:"code"`
		Method             int    `json:"method"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeMessage(w, http.StatusBadRequest, "Bad request")
		return
	}
	if !verifyProvidedMasterHash(*account, req.MasterPasswordHash) {
		if !account.TwoFactorSecret.Valid || !ValidateTOTP(account.TwoFactorSecret.String, req.Code, time.Now().UTC()) {
			writeMessage(w, http.StatusBadRequest, "Invalid password")
			return
		}
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE bitwarden_accounts SET
		two_factor_enabled = 0, two_factor_secret = NULL, updated_at = $1 WHERE user_id = $2`,
		nowBitwarden(), account.UserID); err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to disable two-factor")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// ---- devices ----

func (s *Service) handleKnownDevice(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	deviceID := r.URL.Query().Get("uuid")
	var one int
	err := s.db.QueryRowContext(r.Context(),
		`SELECT 1 FROM bitwarden_devices d JOIN users u ON u.id = d.user_id
		 WHERE d.id = $1 AND u.email = $2`, deviceID, bwcrypto.NormalizeSalt(email)).Scan(&one)
	writeJSON(w, http.StatusOK, err == nil)
}

func (s *Service) handleListDevices(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT id, COALESCE(device_name, ''), COALESCE(device_type, 0), created_at, updated_at, push_token
		 FROM bitwarden_devices WHERE user_id = $1 ORDER BY created_at ASC`, account.UserID)
	if err != nil {
		writeMessage(w, http.StatusInternalServerError, "Unable to load devices")
		return
	}
	defer rows.Close()
	data := []any{}
	for rows.Next() {
		var id, name string
		var deviceType int
		var createdAt, updatedAt string
		var pushToken sql.NullString
		if err := rows.Scan(&id, &name, &deviceType, &createdAt, &updatedAt, &pushToken); err != nil {
			writeMessage(w, http.StatusInternalServerError, "Unable to load devices")
			return
		}
		data = append(data, deviceJSON(id, name, deviceType, createdAt, updatedAt, pushToken))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "object": "list", "continuationToken": nil})
}

func (s *Service) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	device, err := s.deviceByID(r.Context(), account.UserID, r.PathValue("identifier"))
	if err != nil {
		writeMessage(w, http.StatusNotFound, "No device found")
		return
	}
	var createdAt, updatedAt string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT created_at, updated_at FROM bitwarden_devices WHERE id = $1`, device.ID).Scan(&createdAt, &updatedAt)
	writeJSON(w, http.StatusOK, deviceJSON(device.ID, device.Name, device.Type, createdAt, updatedAt, device.PushToken))
}

func deviceJSON(id, name string, deviceType int, createdAt, updatedAt string, pushToken sql.NullString) map[string]any {
	var token any
	if pushToken.Valid {
		token = pushToken.String
	}
	return map[string]any{
		"object":       "device",
		"id":           id,
		"name":         name,
		"type":         deviceType,
		"identifier":   id,
		"creationDate": createdAt,
		"revisionDate": updatedAt,
		"pushToken":    token,
	}
}

func (s *Service) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	account := mustAccount(w, r)
	if account == nil {
		return
	}
	var req struct {
		PushToken string `json:"pushToken"`
	}
	_ = decodeJSON(r, &req)
	_, _ = s.db.ExecContext(r.Context(),
		`UPDATE bitwarden_devices SET push_token = $1 WHERE id = $2 AND user_id = $3`,
		nullableString(&req.PushToken), r.PathValue("identifier"), account.UserID)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// ---- misc ----

// handleBreach provides the manual-check stub upstream serves when no HIBP
// API key is configured, so the client's breach report tab still works.
func (s *Service) handleBreach(w http.ResponseWriter, r *http.Request) {
	if _, ok := FromContext(r.Context()); !ok {
		writeMessage(w, http.StatusUnauthorized, "Not authorized.")
		return
	}
	writeJSON(w, http.StatusOK, []any{map[string]any{
		"name":        "HaveIBeenPwned",
		"title":       "Manual HIBP Check",
		"domain":      "haveibeenpwned.com",
		"breachDate":  "2019-08-18T00:00:00Z",
		"addedDate":   "2019-08-18T00:00:00Z",
		"description": "Configure a Have I Been Pwned API key on the server to enable automatic breach checks, or check manually at haveibeenpwned.com.",
		"logoPath":    "",
		"pwnCount":    0,
		"dataClasses": []string{"Manual check only"},
	}})
}

// mustAccount resolves the authenticated account or writes the 401.
func mustAccount(w http.ResponseWriter, r *http.Request) *accountRecord {
	account, ok := FromContext(r.Context())
	if !ok {
		writeMessage(w, http.StatusUnauthorized, "Not authorized.")
		return nil
	}
	return &account
}
