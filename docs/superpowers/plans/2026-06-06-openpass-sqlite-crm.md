# OpenPass SQLite CRM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-binary OpenPass app with SQLite, admin login, revealable encrypted API keys/secrets, API-key auth, audit logs, and an embedded CRM-style panel.

**Architecture:** Keep the service as Go `net/http` with focused internal packages. Use SQLite via `database/sql` and `modernc.org/sqlite`, AES-GCM for encrypted values, SHA-256 plus timing-safe comparison for API key auth, and static HTML/CSS/JS embedded with `go:embed`.

**Tech Stack:** Go 1.22+, `net/http`, `database/sql`, `modernc.org/sqlite`, vanilla HTML/CSS/JS.

---

## File Map

- Modify: `go.mod` - keep SQLite driver and add no heavy web dependencies.
- Replace: `cmd/server/main.go` - server bootstrap, router registration, embedded web fallback.
- Create: `internal/config/config.go` - read env/config, derive app settings.
- Create: `internal/db/db.go` - open SQLite, apply pragmas and migrations.
- Replace: `migrations/001_init.sql` - SQLite schema for the simplified product.
- Create: `internal/secure/crypto.go` - encryption, hashing, token generation.
- Create: `internal/httpjson/httpjson.go` - consistent JSON helpers.
- Create: `internal/admin/admin.go` - admin sessions and middleware.
- Create: `internal/apikeys/apikeys.go` - API key CRUD, reveal, auth middleware, rate limit.
- Create: `internal/vault/vault.go` - vault and entry CRUD/reveal.
- Create: `internal/audit/audit.go` - audit writes and list queries.
- Create: `internal/web/dist/index.html` - CRM panel shell.
- Create: `internal/web/dist/styles.css` - CRM visual system.
- Create: `internal/web/dist/app.js` - panel behavior and API calls.
- Create: `internal/web/web.go` - embedded static file server.
- Create: focused `_test.go` files for secure, admin, apikeys, vault, and audit behavior.

## Task 1: Runtime Config, Database, And Schema

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/db/db.go`
- Replace: `migrations/001_init.sql`
- Modify: `cmd/server/main.go`

- [ ] Write tests for config defaults and required secret handling.
- [ ] Run targeted config tests and verify they fail before implementation.
- [ ] Implement `Config` with `Addr`, `DatabasePath`, `AdminPassword`, and `SecretKey`.
- [ ] Write tests for SQLite open/migration creating all expected tables.
- [ ] Implement SQLite open with `foreign_keys`, `WAL`, and `busy_timeout`.
- [ ] Replace the migration with the simplified schema.
- [ ] Run `go test ./internal/config ./internal/db`.

## Task 2: Secure Token, Hashing, And Encryption

**Files:**
- Create: `internal/secure/crypto.go`
- Test: `internal/secure/crypto_test.go`

- [ ] Write failing tests for API key format: `op_live_<48 hex chars>`.
- [ ] Write failing tests for prefix, suffix, SHA-256 hash, and timing-safe match.
- [ ] Write failing tests for AES-GCM encrypt/decrypt round trip.
- [ ] Implement generation, SHA-256 hashing, constant-time comparison, and AES-GCM helpers.
- [ ] Run `go test ./internal/secure`.

## Task 3: JSON Helpers And Admin Sessions

**Files:**
- Create: `internal/httpjson/httpjson.go`
- Create: `internal/admin/admin.go`
- Test: `internal/admin/admin_test.go`

- [ ] Write failing tests for login success, login failure, session cookie, and logout.
- [ ] Implement JSON response/error helpers.
- [ ] Implement admin login using `OPENPASS_ADMIN_PASSWORD`.
- [ ] Implement HTTP-only session cookies backed by `admin_sessions`.
- [ ] Implement admin middleware for `/api/admin/*`.
- [ ] Run `go test ./internal/admin`.

## Task 4: API Key Management And Authentication

**Files:**
- Create: `internal/apikeys/apikeys.go`
- Test: `internal/apikeys/apikeys_test.go`

- [ ] Write failing tests for admin key creation storing encrypted token and hash.
- [ ] Write failing tests for reveal returning decrypted token.
- [ ] Write failing tests for revoke making a key unusable.
- [ ] Write failing tests for Bearer auth success and generic unauthorized failures.
- [ ] Write failing tests for permission checks, allowed IP, vault scope, and rate limit.
- [ ] Implement key CRUD, reveal, revoke, API auth middleware, and in-memory sliding-window rate limiter.
- [ ] Run `go test ./internal/apikeys`.

## Task 5: Vaults, Entries, And Revealable Secrets

**Files:**
- Create: `internal/vault/vault.go`
- Test: `internal/vault/vault_test.go`

- [ ] Write failing tests for vault CRUD under admin session.
- [ ] Write failing tests for entry create/list/update/delete.
- [ ] Write failing tests for secret reveal decrypting stored encrypted value.
- [ ] Write failing tests for API key access respecting permissions and vault scope.
- [ ] Implement vault and entry admin/API handlers.
- [ ] Run `go test ./internal/vault`.

## Task 6: Audit Logs

**Files:**
- Create: `internal/audit/audit.go`
- Test: `internal/audit/audit_test.go`

- [ ] Write failing tests for success and denied API key requests creating audit records.
- [ ] Write failing tests for admin audit log listing filters.
- [ ] Implement audit insert and list queries.
- [ ] Integrate audit recording into API key middleware.
- [ ] Run `go test ./internal/audit ./internal/apikeys`.

## Task 7: Embedded CRM Panel

**Files:**
- Create: `internal/web/web.go`
- Create: `internal/web/dist/index.html`
- Create: `internal/web/dist/styles.css`
- Create: `internal/web/dist/app.js`
- Modify: `cmd/server/main.go`

- [ ] Implement embedded static file server with SPA fallback to `index.html`.
- [ ] Build the login screen, dashboard, API keys, vaults, entries, and audit logs views.
- [ ] Add reveal/copy actions for API keys and secrets.
- [ ] Add forms for creating keys, vaults, and entries.
- [ ] Add status badges, filters, and compact CRM-style tables.
- [ ] Run the server and verify the panel loads from `/`.

## Task 8: Bootstrap, Run Script, And Verification

**Files:**
- Modify: `run.sh`
- Create: `.env.example`
- Create: `README.md`

- [ ] Update `run.sh` to build the single binary and run it with SQLite.
- [ ] Document required env vars and production deploy notes.
- [ ] Run `go test ./...`.
- [ ] Run `go build -o bin/openpass-api ./cmd/server`.
- [ ] Start the server and smoke-test login, key creation, reveal, vault entry creation, and API Bearer usage.

## Self-Review

- Spec coverage: the plan covers SQLite, admin-only login, revealable encrypted API keys/secrets, API auth, rate limit, audit logs, frontend embed, and deployment docs.
- Scope control: PostgreSQL, Redis, users, OAuth/OIDC, SDKs, MCP, and SaaS account management remain out of scope.
- Known environment issue: this machine currently does not have `go` on PATH. Verification requires installing or locating Go before test/build commands can pass.
