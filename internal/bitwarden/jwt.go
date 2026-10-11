package bitwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"
)

// jwtAccessTokenTTL matches upstream: access tokens live one hour; clients
// refresh with the refresh token.
const jwtAccessTokenTTL = time.Hour

type serviceKey struct {
	kid string
	key *rsa.PrivateKey
}

var (
	serviceKeyMu    sync.Mutex
	serviceKeyCache map[string]*serviceKey // keyed by DB DSN identity: the *sql.DB
)

// loadOrCreateServiceKey returns the JWT signing key for this server,
// generating a 2048-bit RSA pair on first use. The key lives in the database
// so restarts keep issued tokens verifiable and the JWKS stays stable.
func (s *Service) loadOrCreateServiceKey(ctx context.Context) (*serviceKey, error) {
	serviceKeyMu.Lock()
	defer serviceKeyMu.Unlock()
	if key, ok := serviceKeyCache[string(s.cacheID)]; ok {
		return key, nil
	}

	var pemEncoded string
	var kid string
	err := s.db.QueryRowContext(ctx,
		`SELECT kid, private_key_pem FROM bitwarden_service_keys ORDER BY created_at ASC LIMIT 1`,
	).Scan(&kid, &pemEncoded)

	if err != nil { // no key yet (or query error on a fresh schema race)
		key, genErr := rsa.GenerateKey(rand.Reader, 2048)
		if genErr != nil {
			return nil, genErr
		}
		kid = randomToken(8)
		pemEncoded = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
		if _, insErr := s.db.ExecContext(ctx,
			`INSERT INTO bitwarden_service_keys(kid, private_key_pem, created_at) VALUES($1,$2,$3)`,
			kid, pemEncoded, nowBitwarden(),
		); insErr != nil {
			// Another instance may have inserted first; re-read.
			if rereadErr := s.db.QueryRowContext(ctx,
				`SELECT kid, private_key_pem FROM bitwarden_service_keys ORDER BY created_at ASC LIMIT 1`,
			).Scan(&kid, &pemEncoded); rereadErr != nil {
				return nil, insErr
			}
		}
	}

	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, errors.New("bitwarden service key is not valid PEM")
	}
	key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
	if parseErr != nil {
		return nil, parseErr
	}
	loaded := &serviceKey{kid: kid, key: key}
	if serviceKeyCache == nil {
		serviceKeyCache = map[string]*serviceKey{}
	}
	serviceKeyCache[string(s.cacheID)] = loaded
	return loaded, nil
}

// b64url is the JWS base64url encoding without padding.
func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// signAccessToken issues an RS256 JWT with the claims Bitwarden clients
// expect (sub/e-mail/scope/client_id plus the device block). domain is the
// public base URL of this server, used as the token issuer.
func (s *Service) signAccessToken(key *serviceKey, domain, userID, email, name, clientID string, device deviceRecord, issuedAt, expiresAt time.Time) (string, error) {
	header, err := marshalJOSE(map[string]string{"alg": "RS256", "typ": "JWT", "kid": key.kid})
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"sub":       userID,
		"email":     email,
		"name":      name,
		"premium":   true,
		"scope":     []string{"api"},
		"client_id": clientID,
		"iss":       domain,
		"aud":       "api",
		"nbf":       issuedAt.Unix(),
		"iat":       issuedAt.Unix(),
		"exp":       expiresAt.Unix(),
		"device": map[string]any{
			"Id":         device.ID,
			"Type":       device.Type,
			"Name":       device.Name,
			"Identifier": device.ID,
			"PushToken":  nil,
		},
	}
	body, err := marshalJOSE(claims)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + body
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.key, cryptoSHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(signature), nil
}

// jwksJSON builds the JSON Web Key Set served at /identity/keys.
func (s *Service) jwksJSON(key *serviceKey) map[string]any {
	pub := &key.key.PublicKey
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": key.kid,
			"n":   b64url(pub.N.Bytes()),
			"e":   b64url(bigEndianBytes(pub.E)),
		}},
	}
}

// verifyAccessToken parses and validates one of our JWTs, returning the
// claims. The signature is checked against the stored service key.
func (s *Service) verifyAccessToken(ctx context.Context, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	key, err := s.loadOrCreateServiceKey(ctx)
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if err := rsa.VerifyPKCS1v15(&key.key.PublicKey, cryptoSHA256, digest[:], signature); err != nil {
		return nil, errors.New("invalid signature")
	}
	header, claims, err := decodeJOSE(parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	if kid, _ := header["kid"].(string); kid != key.kid {
		return nil, errors.New("unknown signing key")
	}
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().UTC().Unix() >= int64(exp) {
		return nil, errors.New("token expired")
	}
	return claims, nil
}
