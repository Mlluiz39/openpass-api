package bitwarden

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openpass/api/internal/bitwarden/bwcrypto"
	opdb "github.com/openpass/api/internal/db"
)

// Service implements the Bitwarden-compatible API (identity + api namespaces)
// on top of the OpenPass user table. Vault payloads stay zero-knowledge: the
// server stores CipherStrings it cannot read.
type Service struct {
	db             *sql.DB
	domainOverride string
	// cacheID namespaces the in-memory JWT signing key cache per database.
	cacheID string
}

// New creates the Bitwarden API service. domain, when non-empty, pins the
// public base URL reported by /api/config and used as the JWT issuer
// (env OPENPASS_BW_DOMAIN); otherwise it is derived per request.
func New(database *sql.DB, domain string) *Service {
	return &Service{
		db:             database,
		domainOverride: strings.TrimRight(strings.TrimSpace(domain), "/"),
		cacheID:        fmt.Sprintf("%p", database),
	}
}

// ProvisionUser initializes the Bitwarden-compatible key material for an
// OpenPass account from a plaintext password the panel momentarily knows
// (account creation or password reset). It derives exactly what the client
// would derive, so afterwards the account logs into official clients with
// this password as the Bitwarden master password.
//
// It is idempotent and conservative: once the account has been used from a
// Bitwarden client (i.e. it has registered devices), the key material is
// never overwritten from the panel side — re-wrapping would make the
// existing (client-encrypted) vault undecryptable.
func (s *Service) ProvisionUser(ctx context.Context, userID, password string) error {
	var email string
	if err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		return fmt.Errorf("bitwarden provision: user: %w", err)
	}

	var existingHash sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM bitwarden_accounts WHERE user_id = $1`, userID).Scan(&existingHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if existingHash.Valid && existingHash.String != "" {
		var devices int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bitwarden_devices WHERE user_id = $1`, userID).Scan(&devices); err != nil {
			return err
		}
		if devices > 0 {
			// Already live in Bitwarden clients: the master password may only
			// change through those clients (which re-encrypt the vault).
			return nil
		}
	}

	salt := bwcrypto.NormalizeSalt(email)
	kdf := bwcrypto.DefaultKDF()
	masterKey, err := bwcrypto.DeriveMasterKey(password, salt, kdf)
	if err != nil {
		return err
	}
	passwordHash := bwcrypto.HashMasterKey(masterKey, salt)
	userKey, err := bwcrypto.GenerateUserKey()
	if err != nil {
		return err
	}
	wrappedUserKey, err := bwcrypto.WrapUserKey(masterKey, userKey)
	if err != nil {
		return err
	}
	publicKey, privateKey, err := bwcrypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	encryptedPrivateKey, err := bwcrypto.EncryptPrivateKey(userKey, privateKey)
	if err != nil {
		return err
	}

	now := nowBitwarden()
	_, err = s.db.ExecContext(ctx, `INSERT INTO bitwarden_accounts(
		user_id, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, password_hash,
		user_key, private_key, public_key, security_stamp, created_at, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
	ON CONFLICT (user_id) DO UPDATE SET
		kdf_type = EXCLUDED.kdf_type,
		kdf_iterations = EXCLUDED.kdf_iterations,
		kdf_memory = EXCLUDED.kdf_memory,
		kdf_parallelism = EXCLUDED.kdf_parallelism,
		password_hash = EXCLUDED.password_hash,
		user_key = EXCLUDED.user_key,
		private_key = EXCLUDED.private_key,
		public_key = EXCLUDED.public_key,
		security_stamp = EXCLUDED.security_stamp,
		updated_at = EXCLUDED.updated_at`,
		userID, kdf.Type, kdf.Iterations, nullInt(kdf.MemoryMB), nullInt(kdf.Parallelism),
		passwordHash, wrappedUserKey, encryptedPrivateKey, publicKey, randomUUID(), now,
	)
	if err != nil {
		if opdb.IsUniqueViolation(err) {
			return nil
		}
		return err
	}
	return nil
}

func nullInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

// accountRecord is the join of users and bitwarden_accounts: everything the
// identity and api handlers need about the logged-in account.
type accountRecord struct {
	UserID            string
	Email             string
	Name              string
	Status            string
	Kdf               bwcrypto.KdfParams
	PasswordHash      string
	MasterHint        sql.NullString
	UserKey           string
	PrivateKey        sql.NullString
	PublicKey         sql.NullString
	SecurityStamp     string
	TwoFactorEnabled  bool
	TwoFactorSecret   sql.NullString
	EquivalentDomains string
	ExcludedGlobals   string
	AvatarColor       sql.NullString
	CreatedAt         string
	UpdatedAt         string
}

const accountColumns = `u.id, u.email, COALESCE(u.display_name, ''), u.status, u.created_at, u.updated_at,
	b.kdf_type, b.kdf_iterations, COALESCE(b.kdf_memory, 0), COALESCE(b.kdf_parallelism, 0),
	COALESCE(b.password_hash, ''), b.master_password_hint, COALESCE(b.user_key, ''),
	b.private_key, b.public_key, COALESCE(b.security_stamp, ''), b.two_factor_enabled,
	b.two_factor_secret, b.equivalent_domains, b.excluded_globals, b.avatar_color`

const accountJoin = `FROM users u LEFT JOIN bitwarden_accounts b ON b.user_id = u.id`

func scanAccount(row interface{ Scan(...any) error }) (accountRecord, error) {
	var a accountRecord
	var memory, parallelism int
	var enabled int
	err := row.Scan(&a.UserID, &a.Email, &a.Name, &a.Status, &a.CreatedAt, &a.UpdatedAt,
		&a.Kdf.Type, &a.Kdf.Iterations, &memory, &parallelism,
		&a.PasswordHash, &a.MasterHint, &a.UserKey,
		&a.PrivateKey, &a.PublicKey, &a.SecurityStamp, &enabled,
		&a.TwoFactorSecret, &a.EquivalentDomains, &a.ExcludedGlobals, &a.AvatarColor)
	if err != nil {
		return accountRecord{}, err
	}
	a.Kdf.MemoryMB = memory
	a.Kdf.Parallelism = parallelism
	a.TwoFactorEnabled = enabled == 1
	if a.EquivalentDomains == "" {
		a.EquivalentDomains = "[]"
	}
	if a.ExcludedGlobals == "" {
		a.ExcludedGlobals = "[]"
	}
	return a, nil
}

func (s *Service) accountByEmail(ctx context.Context, email string) (accountRecord, error) {
	return scanAccount(s.db.QueryRowContext(ctx,
		`SELECT `+accountColumns+` `+accountJoin+` WHERE u.email = $1`, bwcrypto.NormalizeSalt(email)))
}

func (s *Service) accountByID(ctx context.Context, userID string) (accountRecord, error) {
	return scanAccount(s.db.QueryRowContext(ctx,
		`SELECT `+accountColumns+` `+accountJoin+` WHERE u.id = $1`, userID))
}

// displayName falls back to the e-mail local part, like upstream falls back
// to the e-mail, so no client ever sees an empty profile name.
func (a accountRecord) displayName() string {
	if strings.TrimSpace(a.Name) != "" {
		return a.Name
	}
	if at := strings.IndexByte(a.Email, '@'); at > 0 {
		return a.Email[:at]
	}
	return a.Email
}

// touchRevision bumps users.updated_at so clients pick up vault changes on
// their next revision-date check.
func (s *Service) touchRevision(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET updated_at = $1 WHERE id = $2`,
		time.Now().UTC().Format(time.RFC3339), userID)
	return err
}

type deviceRecord struct {
	ID                string
	UserID            string
	Name              string
	Type              int
	TwoFactorRemember string
	PushToken         sql.NullString
}

func (s *Service) upsertDevice(ctx context.Context, userID, identifier, name string, deviceType int) (deviceRecord, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return deviceRecord{}, errors.New("device identifier required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Unknown device"
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO bitwarden_devices(
		id, user_id, device_identifier, device_name, device_type, created_at, updated_at
	) VALUES($1,$2,$1,$3,$4,$5,$5)
	ON CONFLICT (id) DO UPDATE SET device_name = EXCLUDED.device_name, device_type = EXCLUDED.device_type, updated_at = EXCLUDED.updated_at`,
		identifier, userID, name, deviceType, nowBitwarden(),
	); err != nil {
		return deviceRecord{}, err
	}
	return s.deviceByID(ctx, userID, identifier)
}

func (s *Service) deviceByID(ctx context.Context, userID, id string) (deviceRecord, error) {
	var d deviceRecord
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, COALESCE(device_name, ''), COALESCE(device_type, 0),
		COALESCE(twofactor_remember, ''), push_token
		FROM bitwarden_devices WHERE id = $1 AND user_id = $2`, id, userID,
	).Scan(&d.ID, &d.UserID, &d.Name, &d.Type, &d.TwoFactorRemember, &d.PushToken)
	if err != nil {
		return deviceRecord{}, err
	}
	return d, nil
}

// issueRefreshToken stores the (hashed) refresh token for a device and
// returns the plaintext token. Rotation simply replaces the stored hash.
func (s *Service) issueRefreshToken(ctx context.Context, deviceID string) (string, error) {
	token := randomToken(32)
	_, err := s.db.ExecContext(ctx,
		`UPDATE bitwarden_devices SET refresh_token_hash = $1, updated_at = $2 WHERE id = $3`,
		hashToken(token), nowBitwarden(), deviceID)
	if err != nil {
		return "", err
	}
	return token, nil
}

func hashToken(token string) string {
	return sha256Hex(token)
}

// deviceByRefreshToken resolves and validates a refresh token, returning the
// owning account and device. The token is rotated by the caller.
func (s *Service) deviceByRefreshToken(ctx context.Context, token string) (accountRecord, deviceRecord, error) {
	var deviceID string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM bitwarden_devices WHERE refresh_token_hash = $1`, hashToken(token)).Scan(&deviceID)
	if err != nil {
		return accountRecord{}, deviceRecord{}, err
	}
	var userID string
	if err := s.db.QueryRowContext(ctx, `SELECT user_id FROM bitwarden_devices WHERE id = $1`, deviceID).Scan(&userID); err != nil {
		return accountRecord{}, deviceRecord{}, err
	}
	account, err := s.accountByID(ctx, userID)
	if err != nil {
		return accountRecord{}, deviceRecord{}, err
	}
	device, err := s.deviceByID(ctx, userID, deviceID)
	return account, device, err
}

// ---- folders ----

type folderRecord struct {
	ID        string
	Name      string
	CreatedAt string
	UpdatedAt string
}

func (s *Service) listFolders(ctx context.Context, userID string) ([]folderRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at, updated_at FROM bitwarden_folders WHERE user_id = $1 ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []folderRecord
	for rows.Next() {
		var f folderRecord
		if err := rows.Scan(&f.ID, &f.Name, &f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Service) folderByID(ctx context.Context, userID, id string) (folderRecord, error) {
	var f folderRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at, updated_at FROM bitwarden_folders WHERE id = $1 AND user_id = $2`, id, userID,
	).Scan(&f.ID, &f.Name, &f.CreatedAt, &f.UpdatedAt)
	return f, err
}

func (s *Service) createFolder(ctx context.Context, userID, name string) (folderRecord, error) {
	id := randomUUID()
	now := nowBitwarden()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO bitwarden_folders(id, user_id, name, created_at, updated_at) VALUES($1,$2,$3,$4,$4)`,
		id, userID, name, now); err != nil {
		return folderRecord{}, err
	}
	return s.folderByID(ctx, userID, id)
}

func (s *Service) updateFolder(ctx context.Context, userID, id, name string) (folderRecord, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE bitwarden_folders SET name = $1, updated_at = $2 WHERE id = $3 AND user_id = $4`,
		name, nowBitwarden(), id, userID)
	if err != nil {
		return folderRecord{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return folderRecord{}, sql.ErrNoRows
	}
	return s.folderByID(ctx, userID, id)
}

func (s *Service) deleteFolder(ctx context.Context, userID, id string) error {
	// Ciphers referencing the folder keep existing, unassigned (matches
	// upstream ON DELETE SET NULL semantics).
	res, err := s.db.ExecContext(ctx, `DELETE FROM bitwarden_folders WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ---- ciphers ----

type cipherRecord struct {
	ID              string
	UserID          string
	FolderID        sql.NullString
	Type            int
	Name            string
	Notes           sql.NullString
	Data            string
	Key             sql.NullString
	Fields          sql.NullString
	PasswordHistory sql.NullString
	Favorite        bool
	Reprompt        int
	DeletedAt       sql.NullString
	CreatedAt       string
	UpdatedAt       string
}

const cipherColumns = `id, user_id, folder_id, type, name, notes, data, key, fields, password_history,
	favorite, reprompt, deleted_date, created_at, updated_at`

func scanCipher(scanner interface{ Scan(...any) error }) (cipherRecord, error) {
	var c cipherRecord
	var favorite int
	err := scanner.Scan(&c.ID, &c.UserID, &c.FolderID, &c.Type, &c.Name, &c.Notes, &c.Data,
		&c.Key, &c.Fields, &c.PasswordHistory, &favorite, &c.Reprompt, &c.DeletedAt,
		&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return cipherRecord{}, err
	}
	c.Favorite = favorite == 1
	return c, nil
}

func (s *Service) listCiphers(ctx context.Context, userID string) ([]cipherRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cipherColumns+` FROM bitwarden_ciphers WHERE user_id = $1 ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cipherRecord
	for rows.Next() {
		c, err := scanCipher(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) cipherByID(ctx context.Context, userID, id string) (cipherRecord, error) {
	return scanCipher(s.db.QueryRowContext(ctx,
		`SELECT `+cipherColumns+` FROM bitwarden_ciphers WHERE id = $1 AND user_id = $2`, id, userID))
}

type cipherInput struct {
	FolderID        *string
	Type            int
	Name            string
	Notes           *string
	Data            string
	Key             *string
	Fields          *string
	PasswordHistory *string
	Favorite        *bool
	Reprompt        *int
}

func (s *Service) createCipher(ctx context.Context, userID string, input cipherInput) (cipherRecord, error) {
	id := randomUUID()
	now := nowBitwarden()
	favorite := 0
	if input.Favorite != nil && *input.Favorite {
		favorite = 1
	}
	reprompt := 0
	if input.Reprompt != nil {
		reprompt = *input.Reprompt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bitwarden_ciphers(
		id, user_id, folder_id, type, name, notes, data, key, fields, password_history,
		favorite, reprompt, created_at, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`,
		id, userID, nullableString(input.FolderID), input.Type, input.Name, nullableString(input.Notes),
		input.Data, nullableString(input.Key), nullableString(input.Fields), nullableString(input.PasswordHistory),
		favorite, reprompt, now,
	)
	if err != nil {
		return cipherRecord{}, err
	}
	if err := s.touchRevision(ctx, userID); err != nil {
		return cipherRecord{}, err
	}
	return s.cipherByID(ctx, userID, id)
}

func (s *Service) updateCipher(ctx context.Context, userID, id string, input cipherInput) (cipherRecord, error) {
	favorite := 0
	if input.Favorite != nil && *input.Favorite {
		favorite = 1
	}
	reprompt := 0
	if input.Reprompt != nil {
		reprompt = *input.Reprompt
	}
	res, err := s.db.ExecContext(ctx, `UPDATE bitwarden_ciphers SET
		folder_id = $1, type = $2, name = $3, notes = $4, data = $5, key = $6, fields = $7,
		password_history = $8, favorite = $9, reprompt = $10, updated_at = $11
		WHERE id = $12 AND user_id = $13`,
		nullableString(input.FolderID), input.Type, input.Name, nullableString(input.Notes),
		input.Data, nullableString(input.Key), nullableString(input.Fields),
		nullableString(input.PasswordHistory), favorite, reprompt, nowBitwarden(), id, userID,
	)
	if err != nil {
		return cipherRecord{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return cipherRecord{}, sql.ErrNoRows
	}
	if err := s.touchRevision(ctx, userID); err != nil {
		return cipherRecord{}, err
	}
	return s.cipherByID(ctx, userID, id)
}

// setCipherDeleted moves a cipher to (or from) the trash.
func (s *Service) setCipherDeleted(ctx context.Context, userID, id string, deleted bool) (cipherRecord, error) {
	var value any
	if deleted {
		value = nowBitwarden()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE bitwarden_ciphers SET deleted_date = $1, updated_at = $2 WHERE id = $3 AND user_id = $4`,
		value, nowBitwarden(), id, userID)
	if err != nil {
		return cipherRecord{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return cipherRecord{}, sql.ErrNoRows
	}
	if err := s.touchRevision(ctx, userID); err != nil {
		return cipherRecord{}, err
	}
	return s.cipherByID(ctx, userID, id)
}

func (s *Service) deleteCipher(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM bitwarden_ciphers WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return s.touchRevision(ctx, userID)
}

func (s *Service) deleteCiphers(ctx context.Context, userID string, ids []string) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM bitwarden_ciphers WHERE id = $1 AND user_id = $2`, id, userID); err != nil {
			return err
		}
	}
	return s.touchRevision(ctx, userID)
}

func (s *Service) restoreCiphers(ctx context.Context, userID string, ids []string) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE bitwarden_ciphers SET deleted_date = NULL, updated_at = $1 WHERE id = $2 AND user_id = $3`,
			nowBitwarden(), id, userID); err != nil {
			return err
		}
	}
	return s.touchRevision(ctx, userID)
}

func (s *Service) emptyTrash(ctx context.Context, userID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM bitwarden_ciphers WHERE user_id = $1 AND deleted_date IS NOT NULL`, userID); err != nil {
		return err
	}
	return s.touchRevision(ctx, userID)
}

func (s *Service) setCipherFavorite(ctx context.Context, userID, id string, favorite bool) (cipherRecord, error) {
	value := 0
	if favorite {
		value = 1
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE bitwarden_ciphers SET favorite = $1, updated_at = $2 WHERE id = $3 AND user_id = $4`,
		value, nowBitwarden(), id, userID)
	if err != nil {
		return cipherRecord{}, err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return cipherRecord{}, sql.ErrNoRows
	}
	if err := s.touchRevision(ctx, userID); err != nil {
		return cipherRecord{}, err
	}
	return s.cipherByID(ctx, userID, id)
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

// ---- request authentication ----

type contextKey string

const bwAccountContextKey contextKey = "bitwarden_account"

// FromContext returns the authenticated Bitwarden account attached by
// requireAuth.
func FromContext(ctx context.Context) (accountRecord, bool) {
	account, ok := ctx.Value(bwAccountContextKey).(accountRecord)
	return account, ok
}

// requireAuth authenticates a request via `Authorization: Bearer <jwt>`,
// validates the account is active and attaches it to the context. Errors
// follow the upstream style: `{"message": "..."}` with 401.
func (s *Service) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header || strings.TrimSpace(token) == "" {
			writeMessage(w, http.StatusUnauthorized, "Not authorized.")
			return
		}
		claims, err := s.verifyAccessToken(r.Context(), token)
		if err != nil {
			writeMessage(w, http.StatusUnauthorized, "Not authorized.")
			return
		}
		userID, _ := claims["sub"].(string)
		account, err := s.accountByID(r.Context(), userID)
		if err != nil || account.Status != "active" || account.UserKey == "" {
			writeMessage(w, http.StatusUnauthorized, "Not authorized.")
			return
		}
		ctx := context.WithValue(r.Context(), bwAccountContextKey, account)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
