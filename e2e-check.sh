#!/usr/bin/env bash
# E2E smoke test: PostgreSQL + multi-user OpenPass.
# Usage: bash e2e-check.sh   (server is built, restarted and left running)
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

# The binary reads the environment, not .env directly — export it like
# deploy.sh does.
[ -f .env ] && set -a && . ./.env && set +a

BASE=http://127.0.0.1:8080
ADMIN_EMAIL="${OPENPASS_ADMIN_EMAIL:-admin@openpass.local}"
ADMIN_PASS="${OPENPASS_ADMIN_PASSWORD:-change-me}"
# Unique per run so re-running the script never collides with a previous run.
USER_EMAIL="user1-$(date +%s)@test.local"
FAIL=0
ok()   { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }
json_get() { python3 -c "import json,sys
try:
    d=json.load(sys.stdin); print(d.get('$1') or '')
except Exception:
    print('')"; }

echo "== build =="
go build -o bin/openpass-api ./cmd/server || { echo "build failed"; exit 1; }

echo "== start server =="
pkill -x openpass-api 2>/dev/null; sleep 1
nohup ./bin/openpass-api > server.log 2>&1 &
for _ in $(seq 1 40); do
  curl -s -o /dev/null "$BASE/" && break
  sleep 0.5
done
if ! curl -s -o /dev/null "$BASE/"; then
  echo "server did not start:"; tail -30 server.log; exit 1
fi
ok "server up (migrations applied at boot)"

JAR_A=$(mktemp); JAR_U=$(mktemp)
trap 'rm -f "$JAR_A" "$JAR_U"' EXIT

# --- admin login -----------------------------------------------------------
RESP=$(curl -s -c "$JAR_A" -X POST "$BASE/api/admin/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}")
if echo "$RESP" | grep -q '"authenticated":true'; then
  ok "admin login (bootstrap account)"
else
  fail "admin login: $RESP"; exit 1
fi

ME=$(curl -s -b "$JAR_A" "$BASE/api/admin/me")
echo "$ME" | grep -q '"role":"admin"' && ok "GET /me returns admin profile" || fail "GET /me: $ME"

# --- invite user -----------------------------------------------------------
RESP=$(curl -s -b "$JAR_A" -X POST "$BASE/api/admin/users" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"display_name\":\"User One\"}")
TEMP=$(echo "$RESP" | json_get "temporary_password")
if [ -n "$TEMP" ]; then
  ok "admin created user, one-time temp password issued"
else
  fail "create user: $RESP"; exit 1
fi

# --- user logs in with temp password, forced change ------------------------
RESP=$(curl -s -c "$JAR_U" -X POST "$BASE/api/admin/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$TEMP\"}")
echo "$RESP" | grep -q '"must_change_password":true' \
  && ok "user login flags must_change_password" || fail "user login: $RESP"

RESP=$(curl -s -b "$JAR_U" -X POST "$BASE/api/admin/change-password" \
  -H 'Content-Type: application/json' \
  -d "{\"current_password\":\"$TEMP\",\"new_password\":\"user-pass-123\"}")
echo "$RESP" | grep -q '"success":true' \
  && ok "forced password change works" || fail "change-password: $RESP"

# --- user creates an entry -------------------------------------------------
RESP=$(curl -s -b "$JAR_U" -X POST "$BASE/api/admin/entries" \
  -H 'Content-Type: application/json' \
  -d '{"path":"segredo","type":"note","value":"user1-secret"}')
ENTRY_ID=$(echo "$RESP" | json_get "id")
[ -n "$ENTRY_ID" ] && ok "user created an entry" || { fail "create entry: $RESP"; exit 1; }

# --- isolation -------------------------------------------------------------
ADMIN_LIST=$(curl -s -b "$JAR_A" "$BASE/api/admin/entries")
if echo "$ADMIN_LIST" | grep -q "$ENTRY_ID"; then
  fail "ISOLATION BROKEN: admin list contains the user's entry"
else
  ok "isolation: admin does NOT see the user's entry"
fi

USER_LIST=$(curl -s -b "$JAR_U" "$BASE/api/admin/entries")
echo "$USER_LIST" | grep -q "$ENTRY_ID" && ok "user sees own entry" || fail "user list: $USER_LIST"

CODE=$(curl -s -b "$JAR_A" -o /dev/null -w '%{http_code}' \
  "$BASE/api/admin/entries/$ENTRY_ID/reveal")
[ "$CODE" = "404" ] && ok "admin reveal of user's entry -> 404" || fail "admin reveal user entry: $CODE"

RESP=$(curl -s -b "$JAR_A" -X POST "$BASE/api/admin/entries" \
  -H 'Content-Type: application/json' \
  -d '{"path":"admin-secret","type":"note","value":"admin-value"}')
AID=$(echo "$RESP" | json_get "id")
REV=$(curl -s -b "$JAR_A" "$BASE/api/admin/entries/$AID/reveal")
echo "$REV" | grep -q 'admin-value' && ok "admin reveals own entry" || fail "admin reveal: $REV"

CODE=$(curl -s -b "$JAR_U" -o /dev/null -w '%{http_code}' \
  -X DELETE "$BASE/api/admin/entries/$AID")
[ "$CODE" = "404" ] && ok "user delete of admin's entry -> 404" || fail "cross delete: $CODE"

# --- role gate -------------------------------------------------------------
CODE=$(curl -s -b "$JAR_U" -o /dev/null -w '%{http_code}' "$BASE/api/admin/users")
[ "$CODE" = "403" ] && ok "non-admin GET /users -> 403" || fail "users gate: $CODE"

RESP=$(curl -s -b "$JAR_A" "$BASE/api/admin/users")
echo "$RESP" | grep -q "$USER_EMAIL" && ok "admin lists accounts" || fail "list users: $RESP"

# --- auth negatives --------------------------------------------------------
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"wrong\"}")
[ "$CODE" = "401" ] && ok "wrong password -> 401" || fail "wrong password: $CODE"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/admin/me")
[ "$CODE" = "401" ] && ok "no cookie GET /me -> 401" || fail "/me no cookie: $CODE"

# --- recovery key flow (per user) ------------------------------------------
KEY=$(curl -s -b "$JAR_U" "$BASE/api/admin/recovery-key" | json_get "recovery_key")
if [ -n "$KEY" ]; then
  ok "user has its own recovery key"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/recover-password" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$USER_EMAIL\",\"recovery_key\":\"OP-REC-WRRN-WRRN-WRRN-WRRN\",\"new_password\":\"x-pass-999\"}")
  [ "$CODE" = "401" ] && ok "wrong recovery key -> 401" || fail "recovery wrong key: $CODE"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/admin/recover-password" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$USER_EMAIL\",\"recovery_key\":\"$(printf '%s' "$KEY" | tr 'A-Z' 'a-z')\",\"new_password\":\"user-pass-456\"}")
  [ "$CODE" = "200" ] && ok "recovery with own key -> 200" || fail "recovery right key: $CODE"
else
  fail "recovery key missing"
fi

# --- migrate-sqlite guard (only when a source DB exists) -------------------
if [ -f data/openpass.db ]; then
  OUT=$(go run ./cmd/migrate-sqlite -sqlite data/openpass.db -admin-email voce@exemplo.com 2>&1 || true)
  if echo "$OUT" | grep -qi 'already has'; then
    ok "migrate-sqlite refuses non-empty target (idempotency guard)"
  else
    fail "migrate-sqlite guard: $OUT"
  fi
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "=== ALL CHECKS PASSED ==="
  echo "Painel no ar: $BASE  (login: $ADMIN_EMAIL / a senha do .env OPENPASS_ADMIN_PASSWORD)"
else
  echo "=== SOME CHECKS FAILED ==="
fi
exit "$FAIL"
