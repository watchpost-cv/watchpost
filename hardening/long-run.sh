#!/bin/sh
set -eu
duration=${WATCHPOST_LONG_RUN_SECONDS:-60}
data=$(mktemp -d); trap 'kill ${pid:-0} 2>/dev/null || true; rm -rf "$data"' EXIT HUP INT TERM
go build -race -o "$data/watchpost" ./cmd/watchpost
"$data/watchpost" serve --listen 127.0.0.1:18090 --data-dir "$data/state" & pid=$!
ready=0
attempt=0
while [ "$attempt" -lt 50 ]; do
  if curl -fsS http://127.0.0.1:18090/readyz >/dev/null 2>&1; then ready=1; break; fi
  attempt=$((attempt + 1))
  sleep 1
done
[ "$ready" -eq 1 ] || { echo 'Watchpost did not become ready' >&2; exit 1; }
end=$(( $(date +%s) + duration ))
while [ "$(date +%s)" -lt "$end" ]; do curl -fsS http://127.0.0.1:18090/readyz >/dev/null; curl -fsS http://127.0.0.1:18090/api/v1/diagnostics >/dev/null; done
kill -TERM "$pid"; wait "$pid"
