#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
TMP=$(mktemp -d)
SERVER_PID=
COLLECTOR_PID=
cleanup() {
  [ -z "$COLLECTOR_PID" ] || kill "$COLLECTOR_PID" 2>/dev/null || true
  [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

PORT=$(python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
)
URL="http://127.0.0.1:$PORT"
BIN="$TMP/watchpost"
(cd "$ROOT" && "$GO_BIN" build -o "$BIN" ./cmd/watchpost)

start_server() {
  "$BIN" --listen "127.0.0.1:$PORT" --data-dir "$TMP/server" >"$TMP/server.log" 2>&1 & SERVER_PID=$!
  for _ in $(seq 1 50); do curl -fsS "$URL/readyz" >/dev/null 2>&1 && return; sleep .1; done
  echo "server did not become ready" >&2; return 1
}
start_collector() {
  "$BIN" collector run --config "$TMP/collector.json" --state "$TMP/queue.json" --interval 1s >"$TMP/collector.log" 2>&1 & COLLECTOR_PID=$!
}

start_server
curl -fsS -X POST "$URL/api/v1/setup" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}' >/dev/null
LOGIN=$(curl -fsS -c "$TMP/cookies" -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}')
CSRF=$(printf '%s' "$LOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"id":"journey-host","name":"Journey host","kind":"host","labels":{}}' >/dev/null
TOKEN_JSON=$(curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts/journey-host/pairing-tokens" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{}')
TOKEN=$(printf '%s' "$TOKEN_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
"$BIN" collector pair --server "$URL" --token "$TOKEN" --id journey-agent --config "$TMP/collector.json" >/dev/null
start_collector

connected=0
for _ in $(seq 1 30); do
  HEALTH=$(curl -fsS -b "$TMP/cookies" "$URL/api/v1/collectors")
  if printf '%s' "$HEALTH" | python3 -c 'import json,sys; raise SystemExit(0 if any(x["status"] in ("healthy","partial") for x in json.load(sys.stdin)["collectors"]) else 1)'; then connected=1; break; fi
  sleep .2
done
[ "$connected" = 1 ] || { echo "collector did not connect" >&2; exit 1; }

kill "$COLLECTOR_PID"; wait "$COLLECTOR_PID" || true; COLLECTOR_PID=
kill "$SERVER_PID"; wait "$SERVER_PID" || true; SERVER_PID=
start_server
start_collector
sleep 2

FROM=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO=$(date -u -d '1 hour' +%Y-%m-%dT%H:%M:%SZ)
HISTORY=$(curl -fsS -b "$TMP/cookies" "$URL/api/v1/posts/journey-host/history?signal=cpu.percent&from=$FROM&to=$TO")
printf '%s' "$HISTORY" | python3 -c 'import json,sys; points=json.load(sys.stdin)["points"]; assert len(points)>=2, points'
echo "two-process host journey passed"
