# OpenPass API

OpenPass is a self-hosted secret manager for agents, automations, and DevOps scripts.

This version is intentionally simple:

- One Go binary serves the API and the CRM-style web panel.
- SQLite stores local data in `data/openpass.db`.
- API keys and secret values are encrypted at rest.
- API keys can be revealed and copied again from the admin panel.
- External callers authenticate with `Authorization: Bearer op_live_...`.

## Run Locally

```bash
export OPENPASS_ADMIN_PASSWORD='choose-a-strong-password'
go run ./cmd/server
```

Open the panel:

```text
http://127.0.0.1:8080/
```

If `OPENPASS_SECRET_KEY` is not set, the app creates `data/openpass.secret`.
Keep that file safe. It is required to decrypt saved API keys and secrets.

### Forgot the password?

The panel password is stored (hashed) in the database, so changing
`OPENPASS_ADMIN_PASSWORD` alone does nothing once a password has been saved.
To force the configured password back, run once with the reset flag:

```bash
OPENPASS_ADMIN_PASSWORD='new-password' OPENPASS_ADMIN_PASSWORD_RESET=1 ./bin/openpass-api
```

This replaces the stored password and invalidates every existing session. Unset
`OPENPASS_ADMIN_PASSWORD_RESET` afterwards.

You can also use the recovery key shown in **⚙️ Segurança**: on the login screen
click **Esqueci minha senha** and paste it.

## Install as an app (PWA)

OpenPass ships a web manifest and a service worker, so it can be installed like
a native app:

- **Android / Chrome / Edge:** an **Instalar app** button appears in the header,
  or use the browser menu → "Instalar OpenPass".
- **iPhone / iPad:** Safari → Share → "Adicionar à Tela de Início".
- **Desktop:** the install icon in the address bar.

Installation requires a **secure context**: HTTPS, or `localhost`. Over plain
HTTP on a remote host the browser will not offer it — terminate TLS in front of
the service (Nginx, Caddy or Cloudflare Tunnel).

The service worker uses network-first for the app shell with a cached offline
fallback. It never intercepts `/api/`, so secrets are always fetched live.

## Build

```bash
go test ./...
go build -o bin/openpass-api ./cmd/server
```

## Deploy / update on a VPS

The web panel is compiled into the binary (`go:embed dist/*`), so **a
`git pull` alone changes nothing** — the running process keeps serving the old
frontend from the binary it was started with. Always rebuild and restart:

```bash
cd /opt/openpass-api     # your checkout
git pull
./deploy.sh              # tests, rebuilds, restarts (systemd or nohup)
```

`deploy.sh` detects an `openpass.service` / `openpass-api.service` unit and uses
`systemctl restart`; with no unit it falls back to `nohup`. Either way it never
touches `data/`, so your records and app key survive.

After an update, reload the page once with **Ctrl+Shift+R** (or Cmd+Shift+R) to
drop the previous assets.

### Behind a Cloudflare Tunnel

Point the tunnel at the port OpenPass listens on (`http://localhost:8080` by
default). Cloudflare terminates TLS, which is what makes the service a secure
context — and therefore what makes **installing as an app (PWA) possible**.
Without HTTPS the browser silently refuses both the service worker and the
install prompt.

- Every response is sent with `Cache-Control: no-store`, so Cloudflare will not
  cache the panel. If you added a "Cache Everything" page rule, remove it or
  purge the cache after deploying.
- Do not put a path prefix in front of the app: the manifest, the service worker
  and its scope all assume the root (`/`).
- The recovery key and backup files stay on the server under `data/`; keep that
  directory in your VPS backups.

## Production Notes

- Persist `data/`, which contains the SQLite database and app key.
- Set `OPENPASS_ADMIN_PASSWORD` outside the repository (e.g. in `.env`).
- Keep `OPENPASS_SECRET_KEY` or `data/openpass.secret` stable.
- Put Nginx, Caddy, Cloudflare Tunnel, or another HTTPS layer in front of the service.
- Run the binary with `systemd` on a VPS.

Example systemd unit (`/etc/systemd/system/openpass.service`):

```ini
[Unit]
Description=OpenPass personal vault
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

## Main Endpoints

Admin panel:

- `POST /api/admin/login`
- `GET /api/admin/keys`
- `POST /api/admin/keys`
- `GET /api/admin/keys/:id/reveal`
- `PATCH /api/admin/keys/:id/revoke`
- `GET /api/admin/vaults`
- `POST /api/admin/vaults`
- `PUT /api/admin/vaults/:id`
- `DELETE /api/admin/vaults/:id`
- `GET /api/admin/entries`
- `POST /api/admin/entries`
- `GET /api/admin/entries/:id/reveal`
- `GET /api/admin/audit-logs`
- `GET /api/admin/backups`
- `DELETE /api/admin/backups`
- `POST /api/admin/backup/export`
- `POST /api/admin/backup/restore`

External API key usage:

- `GET /api/v1/auth/me`
- `GET /api/v1/vaults`
- `GET /api/v1/entries`
- `GET /api/v1/entries/:id`
- `POST /api/v1/entries`
- `PUT /api/v1/entries/:id`
- `DELETE /api/v1/entries/:id`
- `POST /api/v1/backup/create`
- `POST /api/v1/backup/restore`

## Encrypted Backups

The panel has a Backup tab for `.opbackup` files.

- Export with an optional password.
- If the password is empty, the app secret is used.
- Restore needs the same password or the same app secret.
- The backup is a logical JSON snapshot encrypted with AES-GCM.
- Keep both `data/openpass.db` and `data/openpass.secret` backed up for normal VPS operations.

The original app secret is also required to decrypt the secret values and API
keys inside a restored snapshot, **even when the backup has a password**. Keep
that key in a separate safe place; a backup password only protects the outer file.

## Download backups to your device

Open **Backup → Baixar backup neste dispositivo** to download an encrypted
`.opbackup` file through the browser. On a computer or phone, choose the download
location or save it through the browser's file controls. Even when OpenPass runs
on a VPS, the download goes to the device accessing the panel.

You are responsible for keeping the file and sending it to any storage service
you prefer. No Google account, OAuth configuration or cloud integration is needed.
There are no automatic cloud uploads. Local backup history records exports and
restores; it does not contain a downloadable copy of each exported file.

To restore, choose the downloaded file in **Restaurar backup** and enter its
password if one was used. Keep the original app key separately, as explained
above: it is still needed to decrypt the restored secrets and API keys.
