# OpenPass API

OpenPass is a self-hosted, multi-user secret manager for people, agents and
automations.

- One Go binary serves the JSON API and the mobile-first web panel (embedded,
  no frontend build step).
- **PostgreSQL** stores all data (`DATABASE_URL`).
- **Multi-user with invite-only accounts**: each user has an isolated vault —
  entries, API keys, backups and audit logs are scoped by owner. An admin
  manages accounts but cannot read other users' vault data.
- Secrets and API key tokens are encrypted at rest (AES-GCM with the app
  secret). Passwords are hashed with argon2id.
- External callers authenticate with `Authorization: Bearer op_live_...`.

## Quick start (Docker Compose — recommended)

```bash
cp .env.example .env         # set POSTGRES_PASSWORD and OPENPASS_ADMIN_PASSWORD
mkdir -p data && sudo chown 10001 data   # app key directory (container user)
docker compose up -d --build
```

Open `http://127.0.0.1:8080/` and log in with:

- **E-mail:** `OPENPASS_ADMIN_EMAIL` (default `admin@openpass.local`)
- **Password:** `OPENPASS_ADMIN_PASSWORD`

The first admin account is created automatically on an empty database.

## Run locally (without Docker for the app)

```bash
docker compose up -d db              # PostgreSQL only
export OPENPASS_ADMIN_PASSWORD='choose-a-strong-password'
./run.sh                             # tests + build + run
# or: go run ./cmd/server
```

If `OPENPASS_SECRET_KEY` is not set, the app creates `data/openpass.secret`.
Keep that file safe: it is required to decrypt saved API keys and secrets.

### First admin e-mail

`OPENPASS_ADMIN_EMAIL` (default `admin@openpass.local`) is used only when the
`users` table is empty — i.e. to create the very first account.

### Forgot the admin password?

The panel password is stored (hashed) in the database, so changing
`OPENPASS_ADMIN_PASSWORD` alone does nothing once a password has been saved.
To force the configured password back onto the **first admin**, run once with
the reset flag:

```bash
OPENPASS_ADMIN_PASSWORD='new-password' OPENPASS_ADMIN_PASSWORD_RESET=1 ./bin/openpass-api
```

This replaces that admin's stored password and invalidates their sessions.
Unset `OPENPASS_ADMIN_PASSWORD_RESET` afterwards.

You can also use the recovery key shown in **⚙️ Segurança**: on the login
screen click **Esqueci minha senha**, enter your e-mail and the key.

## Users (invite-only)

There is no open registration. An admin creates accounts from **👥 Usuários**
in the panel:

- Each account gets a **temporary password** (generated unless one is typed).
  Copy it immediately — it is shown only once — and share it over a safe
  channel.
- The new user is **forced to change the password** at first login and gets
  their own emergency recovery key.
- Admins can reset a password, disable/enable accounts, change roles and
  delete accounts (deletion cascades to that user's vault, entries, API keys,
  backups and audit logs).
- Roles: `admin` manages accounts; `user` only sees their own vault. Admins
  do **not** get access to other users' vault data.

## Migrate from the old SQLite version

The previous single-user release stored data in `data/openpass.db`. Copy it
into PostgreSQL:

```bash
docker compose up -d db
go run ./cmd/migrate-sqlite \
  -sqlite data/openpass.db \
  -admin-email voce@exemplo.com
```

- All existing vaults, entries, API keys, backups and audit rows become the
  **first admin's data** (e-mail given by `-admin-email`).
- The **old panel password keeps working**: it is carried over in a legacy
  format and transparently upgraded to argon2id on the first successful
  login. The recovery key is carried over as-is.
- Idempotent: re-running skips rows that already exist (`-force` merges into
  a non-empty target).
- Inside Docker: `docker compose run --rm --entrypoint migrate-sqlite app -admin-email voce@exemplo.com`

## Install as an app (PWA)

OpenPass ships a web manifest and a service worker, so it can be installed
like a native app:

- **Android / Chrome / Edge:** an **Instalar app** button appears in the
  header, or use the browser menu → "Instalar OpenPass".
- **iPhone / iPad:** Safari → Share → "Adicionar à Tela de Início".
- **Desktop:** the install icon in the address bar.

Installation requires a **secure context**: HTTPS, or `localhost`. Over plain
HTTP on a remote host the browser will not offer it — terminate TLS in front
of the service (Nginx, Caddy or Cloudflare Tunnel).

The service worker uses network-first for the app shell with a cached offline
fallback. It never intercepts `/api/`, so secrets are always fetched live.

## Build and test

```bash
docker compose up -d db      # tests run against PostgreSQL
go test ./...
go build -o bin/openpass-api ./cmd/server
```

Every test gets an isolated PostgreSQL schema (`internal/db.OpenTest`), so
tests never touch your dev data. The connection comes from
`OPENPASS_TEST_DATABASE_URL` (defaults to the local dev database URL).

## Deploy / update on a VPS

The panel is compiled into the binary and the image is built from source, so
**a `git pull` alone changes nothing** — always rebuild and restart:

```bash
cd /opt/openpass-api     # your checkout
git pull
./deploy.sh              # tests, rebuild, restart
```

- With `docker-compose.yml` present (recommended): `deploy.sh` runs the tests
  against the compose database and does `docker compose up -d --build app`.
- Without Docker it falls back to the classic path: `go test`, `go build`,
  then `systemctl restart` (unit `openpass` / `openpass-api`) or `nohup`.

Set `SKIP_TESTS=1` to skip the test run (e.g. when PostgreSQL is down).

After an update, reload the page once with **Ctrl+Shift+R** (or Cmd+Shift+R)
to drop the previous assets.

### Behind a Cloudflare Tunnel

Point the tunnel at the port OpenPass listens on (`http://localhost:8080` by
default). Cloudflare terminates TLS, which is what makes the service a secure
context — and therefore what makes **installing as an app (PWA) possible**.
Without HTTPS the browser silently refuses both the service worker and the
install prompt.

- Every response is sent with `Cache-Control: no-store`, so Cloudflare will
  not cache the panel. If you added a "Cache Everything" page rule, remove it
  or purge the cache after deploying.
- Do not put a path prefix in front of the app: the manifest, the service
  worker and its scope all assume the root (`/`).

## Production notes

- **Database:** persist the `pgdata` Docker volume (or back up PostgreSQL
  with `pg_dump`). All vault data lives there.
- **App key:** persist `./data/` (holds `openpass.secret`). Without it,
  encrypted secrets cannot be decrypted. Keep it in a *separate* backup from
  the database.
- Set `POSTGRES_PASSWORD`, `OPENPASS_ADMIN_PASSWORD` and (optionally)
  `OPENPASS_SECRET_KEY` in `.env`, outside the repository.
- Put Nginx, Caddy, Cloudflare Tunnel, or another HTTPS layer in front.

Example systemd unit when **not** using Docker
(`/etc/systemd/system/openpass.service`):

```ini
[Unit]
Description=OpenPass vault
After=network.target

[Service]
Type=simple
User=openpass
WorkingDirectory=/opt/openpass-api
EnvironmentFile=/opt/openpass-api/.env
ExecStart=/opt/openpass-api/bin/openpass-api
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Main endpoints

Session (panel; cookie `openpass_session`, scoped to the logged-in user):

- `POST /api/admin/login` — `{email, password}`
- `POST /api/admin/logout`
- `GET /api/admin/me` — profile + `must_change_password`
- `POST /api/admin/change-password`
- `GET /api/admin/recovery-key` / `POST /api/admin/regenerate-recovery-key`
- `POST /api/admin/recover-password` — `{email, recovery_key, new_password}`

Accounts (admin role only):

- `GET /api/admin/users`
- `POST /api/admin/users` — `{email, display_name, role, password?}`
- `PATCH /api/admin/users/{id}` — status/role/display_name/reset_password
- `DELETE /api/admin/users/{id}`

Vault (session, owner-scoped):

- `GET/POST /api/admin/vaults`, `PUT/DELETE /api/admin/vaults/{id}`
- `GET/POST /api/admin/entries`, `PUT/DELETE /api/admin/entries/{id}`
- `GET /api/admin/entries/{id}/reveal`
- `GET /api/admin/audit-logs` — own API-key traffic only
- `GET/DELETE /api/admin/backups`
- `POST /api/admin/backup/export` / `POST /api/admin/backup/restore`

External API key usage (Bearer, scoped to the key owner):

- `GET /api/v1/auth/me`
- `GET /api/v1/vaults`, `GET /api/v1/vaults/{id}`
- `GET /api/v1/entries`, `GET /api/v1/entries/{id}`
- `POST /api/v1/entries`, `PUT /api/v1/entries/{id}`, `DELETE /api/v1/entries/{id}`
- `POST /api/v1/backup/create`, `POST /api/v1/backup/restore`

## Encrypted backups

The panel has a Backup tab for `.opbackup` files. Backups are **per user**:
an export contains only the exporting account's rows.

- Export with an optional password. If the password is empty, the app secret
  is used.
- Restore needs the same password or the same app secret, and only replaces
  the restoring user's data (other accounts are untouched).
- The backup is a logical JSON snapshot encrypted with AES-GCM.

The app secret is also required to decrypt the secret values and API keys
inside a restored snapshot, **even when the backup has a password**. Keep
that key in a separate safe place; a backup password only protects the outer
file.

To restore, choose the downloaded file in **Restaurar backup** and enter its
password if one was used.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgres://openpass:openpass@localhost:5432/openpass?sslmode=disable` | PostgreSQL connection string |
| `OPENPASS_TEST_DATABASE_URL` | same host/db as dev | connection for `go test` (schema-per-test) |
| `OPENPASS_ADDR` | `:8080` | listen address |
| `OPENPASS_ADMIN_EMAIL` | `admin@openpass.local` | e-mail of the first admin (empty DB only) |
| `OPENPASS_ADMIN_PASSWORD` | generated + logged | password of the first admin / CLI reset value |
| `OPENPASS_ADMIN_PASSWORD_RESET` | unset | `1` = overwrite first admin's password, kill their sessions |
| `OPENPASS_SECRET_KEY` | from `OPENPASS_SECRET_FILE` | app encryption key (keep stable!) |
| `OPENPASS_SECRET_FILE` | `data/openpass.secret` | where the app key is created/stored |
| `POSTGRES_PASSWORD` | — | database password for compose |
| `POSTGRES_PORT` | `5432` | host port mapped to the db container |
| `OPENPASS_PORT` | `8080` | host port mapped to the app |
