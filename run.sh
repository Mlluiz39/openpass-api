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

mkdir -p bin data backups

echo "[1/3] Running tests..."
go test ./...

echo "[2/3] Building OpenPass..."
go build -o bin/openpass-api ./cmd/server

echo "[3/3] Starting OpenPass..."
nohup ./bin/openpass-api > server.log 2>&1 &
echo "PID=$!"
sleep 1

echo "Panel: http://127.0.0.1:8080/"
echo "Logs: tail -f server.log"
