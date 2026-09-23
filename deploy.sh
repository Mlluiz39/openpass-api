#!/bin/bash
#
# Rebuild and restart OpenPass after a `git pull`.
#
# The frontend is compiled into the binary (go:embed dist/*), so pulling the
# source changes nothing until the binary is rebuilt and the service restarted.
# This script does both and keeps data/ untouched.
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ---------------------------------------------------------------- toolchain
if ! command -v go >/dev/null 2>&1; then
  export PATH="$PATH:/usr/local/go/bin"
fi
if ! command -v go >/dev/null 2>&1; then
  echo "ERRO: Go nao encontrado. Instale o Go 1.22+ ou adicione ao PATH." >&2
  exit 1
fi

echo "==> Go: $(go version)"

# ------------------------------------------------------------------- config
# shellcheck disable=SC1091
[ -f .env ] && set -a && . ./.env && set +a

if [ -z "${OPENPASS_ADMIN_PASSWORD:-}" ]; then
  echo "AVISO: OPENPASS_ADMIN_PASSWORD nao definido. A senha atual do banco continua valendo."
  echo "       Para redefinir, use OPENPASS_ADMIN_PASSWORD_RESET=1 (veja o README)."
fi

# -------------------------------------------------------------------- build
echo "==> Rodando testes..."
go test ./...

echo "==> Compilando..."
mkdir -p bin data
go build -o bin/openpass-api ./cmd/server
echo "    bin/openpass-api atualizado ($(date -r bin/openpass-api '+%Y-%m-%d %H:%M:%S'))"

# ------------------------------------------------------------------ restart
restart_systemd() {
  local unit="$1"
  echo "==> Reiniciando via systemd ($unit)..."
  sudo systemctl restart "$unit"
  sleep 1
  systemctl is-active --quiet "$unit" && echo "    ativo" || {
    echo "ERRO: $unit nao subiu. Veja: journalctl -u $unit -n 50" >&2
    exit 1
  }
}

restart_nohup() {
  echo "==> Reiniciando via nohup..."
  if pgrep -x openpass-api >/dev/null 2>&1; then
    pkill -x openpass-api || true
    for _ in $(seq 1 20); do
      pgrep -x openpass-api >/dev/null 2>&1 || break
      sleep 0.25
    done
  fi
  nohup ./bin/openpass-api > server.log 2>&1 &
  sleep 1
  if pgrep -x openpass-api >/dev/null 2>&1; then
    echo "    PID $(pgrep -x openpass-api) - log em server.log"
  else
    echo "ERRO: nao subiu. Veja server.log:" >&2
    tail -n 20 server.log >&2 || true
    exit 1
  fi
}

# A systemd unit named openpass or openpass-api wins if one is installed.
if command -v systemctl >/dev/null 2>&1; then
  for unit in openpass openpass-api; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${unit}\.service"; then
      restart_systemd "$unit"
      FQDN_HINT="$(hostname -f 2>/dev/null || hostname)"
      echo
      echo "Pronto. Acesse o painel, e recarregue com Ctrl+Shift+R na primeira vez."
      exit 0
    fi
  done
fi

restart_nohup
echo
echo "Pronto. Acesse o painel e recarregue com Ctrl+Shift+R na primeira vez."
