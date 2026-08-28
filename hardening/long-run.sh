#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); GO_BIN=${GO_BIN:-go}; DURATION=${WATCHPOST_LONG_RUN_SECONDS:-60}
MAX_HEAP_BYTES=${WATCHPOST_MAX_HEAP_BYTES:-536870912}; MAX_FDS=${WATCHPOST_MAX_FDS:-256}; MAX_GOROUTINES=${WATCHPOST_MAX_GOROUTINES:-512}; MAX_DB_BYTES=${WATCHPOST_MAX_DB_BYTES:-134217728}
TMP=$(mktemp -d); SERVER_PID=; COLLECTOR_PID=
cleanup(){ [ -z "$COLLECTOR_PID" ] || kill "$COLLECTOR_PID" 2>/dev/null || true; [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
PORT=$(python3 - <<'PY'
import socket
s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()
PY
)
URL="http://127.0.0.1:$PORT"; BIN="$TMP/watchpost"; (cd "$ROOT" && "$GO_BIN" build -race -o "$BIN" ./cmd/watchpost)
"$BIN" --listen "127.0.0.1:$PORT" --data-dir "$TMP/state" >"$TMP/server.log" 2>&1 & SERVER_PID=$!
for _ in $(seq 1 50); do curl -fsS "$URL/readyz" >/dev/null 2>&1 && break; sleep .1; done
curl -fsS -X POST "$URL/api/v1/setup" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}' >/dev/null
LOGIN=$(curl -fsS -c "$TMP/cookies" -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}')
CSRF=$(printf '%s' "$LOGIN" | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf_token"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"id":"soak-host","name":"Soak host","kind":"host","labels":{}}' >/dev/null
TOKEN=$(curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts/soak-host/pairing-tokens" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
"$BIN" collector pair --server "$URL" --token "$TOKEN" --id soak-agent --config "$TMP/collector.json" >/dev/null
"$BIN" collector run --config "$TMP/collector.json" --state "$TMP/queue.json" --interval 1s >"$TMP/collector.log" 2>&1 & COLLECTOR_PID=$!
end=$(( $(date +%s) + DURATION )); max_heap=0; max_fds=0; max_goroutines=0
while [ "$(date +%s)" -lt "$end" ]; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null || ! kill -0 "$COLLECTOR_PID" 2>/dev/null; then cat "$TMP/server.log" "$TMP/collector.log" >&2; exit 1; fi
  curl -fsS "$URL/readyz" >/dev/null; curl -fsS -b "$TMP/cookies" "$URL/api/v1/survey" >/dev/null
  read -r heap fds goroutines < <(curl -fsS "$URL/api/v1/diagnostics" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["heap_alloc_bytes"],d["open_fds"],d["goroutines"])')
  [ "$heap" -le "$MAX_HEAP_BYTES" ]; [ "$fds" -lt 0 ] || [ "$fds" -le "$MAX_FDS" ]; [ "$goroutines" -le "$MAX_GOROUTINES" ]
  [ "$heap" -le "$max_heap" ] || max_heap=$heap; [ "$fds" -le "$max_fds" ] || max_fds=$fds; [ "$goroutines" -le "$max_goroutines" ] || max_goroutines=$goroutines
  sleep .2
done
db_size=$(stat -c %s "$TMP/state/watchpost.db"); [ "$db_size" -le "$MAX_DB_BYTES" ]
kill "$COLLECTOR_PID"; wait "$COLLECTOR_PID"; COLLECTOR_PID=; kill "$SERVER_PID"; wait "$SERVER_PID"; SERVER_PID=
! grep -q 'DATA RACE' "$TMP/server.log" "$TMP/collector.log"
echo "long-run passed: max_heap_bytes=$max_heap max_fds=$max_fds max_goroutines=$max_goroutines db_bytes=$db_size duration_seconds=$DURATION"
