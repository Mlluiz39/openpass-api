#!/bin/bash
set -e

BIN_NAME="openpass-api"

echo "[1/4] Checking Go..."
if ! command -v go >/dev/null 2>&1; then
  echo "Go not found in PATH. Trying /usr/local/go/bin/go..."
  if [ -x /usr/local/go/bin/go ]; then
    export PATH="$PATH:/usr/local/go/bin"
  else
    echo "ERROR: Go not installed."
    exit 1
  fi
fi
go version

echo "[2/4] Building..."
go build -o "$BIN_NAME" ./cmd/server

echo "[3/4] Ensuring data dir..."
mkdir -p data backups

echo "[4/4] Starting server on :8080..."
nohup ./"$BIN_NAME" > server.log 2>&1 &
echo "PID=$!"
echo "API available at:"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
