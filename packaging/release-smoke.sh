#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
TMP=$(mktemp -d)
PID=
HTTP_PID=
ACTIVE=
cleanup(){ [ -z "$PID" ] || kill "$PID" 2>/dev/null || true; [ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

cd "$ROOT"
PATH="$(dirname "$GO_BIN"):$PATH" ./packaging/build-release.sh v0.0.0-smoke
[ "$(find dist -maxdepth 1 -type f | wc -l)" -eq 13 ]
first=$(sha256sum dist/* | sha256sum)
PATH="$(dirname "$GO_BIN"):$PATH" ./packaging/build-release.sh v0.0.0-smoke
second=$(sha256sum dist/* | sha256sum)
[ "$first" = "$second" ]
dist/watchpost-v0.0.0-smoke-linux-amd64 --version | grep -qx 'v0.0.0-smoke'
for archive in dist/*.tar.gz; do tar -tzf "$archive" | grep -x watchpost >/dev/null; done
for archive in dist/*.zip; do unzip -Z1 "$archive" | grep -x watchpost.exe >/dev/null; done
(cd dist && sha256sum -c SHA256SUMS)
cp dist/watchpost-v0.0.0-smoke-linux-amd64 "$TMP/old"

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
)
URL="http://127.0.0.1:$PORT"
start(){ "$ACTIVE" --listen "127.0.0.1:$PORT" --data-dir "$TMP/state" >"$TMP/server.log" 2>&1 & PID=$!; for _ in $(seq 1 50); do curl -fsS "$URL/readyz" >/dev/null 2>&1 && return; sleep .1; done; return 1; }
stop(){ kill "$PID"; wait "$PID"; PID=; }
ACTIVE="$TMP/old"; start
curl -fsS -X POST "$URL/api/v1/setup" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}' >/dev/null
LOGIN=$(curl -fsS -c "$TMP/cookies" -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}')
CSRF=$(printf '%s' "$LOGIN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf_token"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"id":"release-post","name":"Release post","kind":"host","labels":{}}' >/dev/null
stop
PATH="$(dirname "$GO_BIN"):$PATH" ./packaging/build-release.sh v0.0.1-smoke
cp dist/watchpost-v0.0.1-smoke-linux-amd64 "$TMP/new"; ACTIVE="$TMP/new"; start
curl -fsS -b "$TMP/cookies" "$URL/api/v1/posts" | python3 -c 'import json,sys;assert any(x["id"]=="release-post" for x in json.load(sys.stdin)["posts"])'
stop
ACTIVE="$TMP/old"; start
curl -fsS -b "$TMP/cookies" "$URL/api/v1/posts" | python3 -c 'import json,sys;assert any(x["id"]=="release-post" for x in json.load(sys.stdin)["posts"])'
stop

mkdir -p "$TMP/releases/v0.0.1-smoke"; cp dist/* "$TMP/releases/v0.0.1-smoke/"
python3 -m http.server 18091 --bind 127.0.0.1 --directory "$TMP/releases" >"$TMP/http.log" 2>&1 & HTTP_PID=$!
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:18091/v0.0.1-smoke/SHA256SUMS >/dev/null 2>&1 && break; sleep .1; done
mkdir -p "$TMP/home" "$TMP/bin"; chmod 777 "$TMP/home" "$TMP/bin"
if [ "$(id -u)" -eq 0 ]; then
  env HOME="$TMP/home" PATH="$PATH" WATCHPOST_VERSION=v0.0.1-smoke WATCHPOST_RELEASE_BASE=http://127.0.0.1:18091 WATCHPOST_INSTALL_DIR="$TMP/bin" sh ./install.sh --system
else
  env HOME="$TMP/home" WATCHPOST_VERSION=v0.0.1-smoke WATCHPOST_RELEASE_BASE=http://127.0.0.1:18091 WATCHPOST_INSTALL_DIR="$TMP/bin" sh ./install.sh
fi
"$TMP/bin/watchpost" --version | grep -qx 'v0.0.1-smoke'
echo 'release artifact, installer, upgrade, and rollback smoke passed'
