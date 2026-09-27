#!/bin/bash
set -euo pipefail

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$REPO_DIR"

if ! command -v go >/dev/null 2>&1; then
  export PATH="$PATH:/usr/local/go/bin"
fi

if ! command -v go >/dev/null 2>&1; then
  echo "Go not found. Install Go 1.22+ or add it to PATH."
  exit 1
fi

if [ -z "${OPENPASS_ADMIN_PASSWORD:-}" ]; then
  echo "OPENPASS_ADMIN_PASSWORD is not set. The server will print a temporary password."
fi

# Tests and the server talk to PostgreSQL. If docker compose is available,
# make sure the dev database is up first (best effort).
if [ -f docker-compose.yml ] && command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "[0/4] Ensuring PostgreSQL is up (docker compose)..."
  docker compose up -d db || echo "  (compose unavailable; assuming Postgres is reachable another way)"
fi

mkdir -p bin data backups

# Match the process name exactly (-x): "pkill -f bin/openpass-api" would also
# match this script's own command line and kill the running shell.
if pgrep -x openpass-api >/dev/null 2>&1; then
  echo "[1/4] Stopping the running OpenPass instance..."
  pkill -x openpass-api || true
  for _ in $(seq 1 20); do
    pgrep -x openpass-api >/dev/null 2>&1 || break
    sleep 0.25
  done
else
  echo "[1/4] No running OpenPass instance."
fi

echo "[2/4] Running tests..."
go test ./...

echo "[3/4] Building OpenPass..."
go build -o bin/openpass-api ./cmd/server

echo "[4/4] Starting OpenPass..."
nohup ./bin/openpass-api > server.log 2>&1 &
echo "PID=$!"
sleep 1

echo "Panel: http://127.0.0.1:8080/"
echo "Logs: tail -f server.log"
