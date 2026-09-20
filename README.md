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

## Build

```bash
go test ./...
go build -o bin/openpass-api ./cmd/server
```

## Production Notes

- Persist `data/`, which contains the SQLite database and app key.
- Set `OPENPASS_ADMIN_PASSWORD` outside the repository.
- Keep `OPENPASS_SECRET_KEY` or `data/openpass.secret` stable.
- Put Nginx, Caddy, Cloudflare Tunnel, or another HTTPS layer in front of the service.
- Run the binary with `systemd` on a VPS.

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
