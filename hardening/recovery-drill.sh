#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); GO_BIN=${GO_BIN:-go}; TMP=$(mktemp -d); PID=
cleanup(){ [ -z "$PID" ] || kill "$PID" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMP"; }; trap cleanup EXIT
PORT=$(python3 - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
)
URL="http://127.0.0.1:$PORT"; BIN="$TMP/watchpost"; (cd "$ROOT" && "$GO_BIN" build -o "$BIN" ./cmd/watchpost)
start(){ "$BIN" --listen "127.0.0.1:$PORT" --data-dir "$1" >"$TMP/server.log" 2>&1 & PID=$!; for _ in $(seq 1 50);do curl -fsS "$URL/readyz" >/dev/null 2>&1&&return;sleep .1;done;return 1; }
stop(){ kill "$PID";wait "$PID";PID=; }
start "$TMP/live"
curl -fsS -X POST "$URL/api/v1/setup" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}' >/dev/null
LOGIN=$(curl -fsS -c "$TMP/cookies" -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}')
CSRF=$(printf '%s' "$LOGIN"|python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf_token"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"id":"recovery-post","name":"Recovery post","kind":"host","labels":{}}' >/dev/null
stop; mkdir "$TMP/backup"; cp "$TMP/live/watchpost.db" "$TMP/backup/watchpost.db"; chmod 600 "$TMP/backup/watchpost.db"
mkdir "$TMP/restored"; cp "$TMP/backup/watchpost.db" "$TMP/restored/watchpost.db"; start "$TMP/restored"
curl -fsS -b "$TMP/cookies" "$URL/api/v1/posts" | python3 -c 'import json,sys;assert any(x["id"]=="recovery-post" for x in json.load(sys.stdin)["posts"])'
stop; mkdir "$TMP/corrupt"; printf 'not sqlite' >"$TMP/corrupt/watchpost.db"
if "$BIN" --listen "127.0.0.1:0" --data-dir "$TMP/corrupt" >"$TMP/corrupt.log" 2>&1; then echo 'corrupt database started' >&2; exit 1; fi
echo 'stopped backup, restore, and corruption drill passed'
