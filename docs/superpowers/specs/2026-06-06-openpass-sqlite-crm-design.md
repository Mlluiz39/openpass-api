# OpenPass SQLite CRM Design

Date: 2026-06-06
Status: Approved for implementation planning

## Goal

Build a simple self-hosted OpenPass application as a single Go service that serves both the API and an embedded web panel. The product keeps the API key/security goals from the PRD, but intentionally avoids operational complexity: no PostgreSQL, no Redis, no multi-user account system, and no separate frontend server.

## Scope

The first production-ready scope is:

- Single admin login protected by a password.
- SQLite database stored under `data/openpass.db`.
- Go `net/http` backend.
- Static HTML/CSS/JS frontend embedded into the Go binary, with no separate frontend build step.
- CRM-style admin panel for API keys, vaults, secrets, and audit logs.
- API keys usable by external agents and automations through `Authorization: Bearer`.
- Secrets and API keys revealable/copyable from the admin panel after login.
- Encrypted-at-rest storage for revealable secrets and API key plaintext tokens.

Out of scope for this iteration:

- Multiple human users.
- PostgreSQL.
- Redis.
- OAuth/OIDC.
- Separate SaaS-style account management.
- Full MCP server integration.

## Core Decisions

### SQLite Instead Of PostgreSQL

The app uses SQLite for simplicity and self-hosting. The database layer enables:

- `PRAGMA foreign_keys = ON`
- `PRAGMA journal_mode = WAL`
- `PRAGMA busy_timeout = 5000`

The application owns migrations and applies them at startup.

### Single Admin

There is one admin identity. The admin password comes from configuration:

- Preferred: `OPENPASS_ADMIN_PASSWORD`
- If missing on first run, the app may generate and print a temporary setup password.

The web panel login creates an HTTP-only session cookie. Admin sessions are stored in SQLite and can be revoked by clearing sessions.

### Revealable API Keys

Unlike the original PRD rule, API keys are revealable after creation because this self-hosted version is intended for frequent operational copying.

For each API key:

- The token plaintext is encrypted at rest.
- A SHA-256 hash is stored for authentication.
- `key_prefix` is stored for lookup.
- `key_suffix` is stored for display.
- The full token is never logged.
- The panel can reveal/copy the token only after admin authentication.

### Revealable Secrets

Vault entries are also revealable/copyable from the panel. Secret values are encrypted at rest and decrypted only for authenticated admin panel requests or authorized API key requests.

### Encryption Key

The app uses an application encryption key from:

- `OPENPASS_SECRET_KEY`

This key protects stored API key plaintext tokens and secret values. If it is missing on first run, the app can generate one and persist it in a local config file with restrictive file permissions where the OS supports it.

## API Key Security

API key format:

```text
op_live_<48 hex chars>
op_test_<48 hex chars>
```

Authentication flow:

1. Read `Authorization: Bearer <token>`.
2. Extract `key_prefix`.
3. Query active keys by `key_prefix`.
4. Compute SHA-256 of the received token.
5. Compare using `crypto/subtle.ConstantTimeCompare`.
6. Check expiration.
7. Check allowed IPs if configured.
8. Check required permission.
9. Apply in-memory sliding-window rate limit.
10. Write audit log for success and denial.
11. Update `last_used_at`.

Invalid, expired, revoked, or mismatched keys return a generic:

```json
{ "error": "unauthorized" }
```

## Data Model

Tables:

- `admin_sessions`
- `api_keys`
- `vaults`
- `entries`
- `backups`
- `api_audit_logs`

`api_keys` stores:

- `id`
- `name`
- `description`
- `key_prefix`
- `key_hash`
- `key_suffix`
- `encrypted_token`
- `permissions`
- `allowed_ips`
- `vault_scope`
- `rate_limit_rpm`
- `is_active`
- `last_used_at`
- `expires_at`
- `created_at`
- `updated_at`

`entries` stores encrypted secret values:

- `id`
- `vault_id`
- `path`
- `type`
- `encrypted_value`
- `metadata`
- `tags`
- `created_at`
- `updated_at`

Audit logs include:

- API key id or key prefix when known
- IP address
- user agent
- method
- endpoint
- request id
- status code
- duration
- result: `success`, `denied`, or `error`
- error message when safe
- timestamp

## Backend Structure

```text
cmd/server/main.go
internal/config/
internal/db/
internal/crypto/
internal/httpjson/
internal/admin/
internal/apikeys/
internal/vault/
internal/audit/
internal/ratelimit/
internal/web/
migrations/
internal/web/dist/
```

`internal/web` owns the `go:embed` directive and serves the built frontend assets.

## HTTP Surface

Admin/session endpoints:

- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/me`

Admin panel API:

- `GET /api/admin/keys`
- `POST /api/admin/keys`
- `PATCH /api/admin/keys/:id`
- `PATCH /api/admin/keys/:id/revoke`
- `DELETE /api/admin/keys/:id`
- `GET /api/admin/keys/:id/reveal`
- `GET /api/admin/keys/:id/logs`
- `GET /api/admin/vaults`
- `POST /api/admin/vaults`
- `GET /api/admin/entries`
- `POST /api/admin/entries`
- `PUT /api/admin/entries/:id`
- `DELETE /api/admin/entries/:id`
- `GET /api/admin/entries/:id/reveal`
- `GET /api/admin/audit-logs`

External API key endpoints:

- `GET /api/v1/auth/me`
- `GET /api/v1/vaults`
- `GET /api/v1/vaults/:id`
- `GET /api/v1/entries`
- `GET /api/v1/entries/:id`
- `POST /api/v1/entries`
- `PUT /api/v1/entries/:id`
- `DELETE /api/v1/entries/:id`
- `POST /api/v1/backup/create`
- `POST /api/v1/backup/restore`

## Frontend Design

The panel is implemented as static HTML/CSS/JS served by Go. It should feel like a compact CRM or operational console:

- Persistent sidebar.
- Dense dashboard metrics.
- Searchable and filterable tables.
- Clear status badges for active, revoked, expired, and rate-limited keys.
- Detail drawers or modals for editing records.
- Reveal/copy controls for API keys and secrets.
- Audit log table with filters for key, endpoint, IP, status, and date.

The first screen after login is the dashboard, not a marketing page.

## Error Handling

- Admin endpoints return clear validation errors.
- API key endpoints avoid leaking authentication failure details.
- JSON responses use consistent envelopes.
- Audit logging must not block successful responses when a log write fails, but failures should be written to server logs.

## Testing

Minimum automated coverage:

- API key generation format, prefix, suffix, and SHA-256 hash.
- Timing-safe authentication path.
- Encryption and decryption round trip.
- Admin login/session lifecycle.
- Permission enforcement.
- Vault scope enforcement.
- Allowed IP enforcement.
- Rate limit response headers.
- Audit log creation for success and denied requests.

## Deployment

The deployment target is a single binary:

```text
openpass-api
data/openpass.db
```

Recommended deployment:

- `systemd` runs the binary.
- Nginx or Cloudflare Tunnel provides HTTPS.
- `data/` is persisted and backed up.
- `OPENPASS_ADMIN_PASSWORD` and `OPENPASS_SECRET_KEY` are configured outside the repository.

## Open Questions Resolved

- API keys are revealable after creation: yes.
- Secrets are revealable after creation: yes.
- Human users: single admin only.
- Database: SQLite.
- Frontend: embedded into Go binary.
- UI style: CRM-style operational panel.
