#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO_BIN=${GO_BIN:-go}
TMP=$(mktemp -d)
SERVER_PID=
cleanup() {
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

start_server
curl -fsS -X POST "$URL/api/v1/setup" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}' >/dev/null
LOGIN=$(curl -fsS -c "$TMP/cookies" -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' --data '{"email":"admin@example.com","password":"1234567"}')
CSRF=$(printf '%s' "$LOGIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/posts" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"id":"journey-host","name":"Journey host","kind":"host","labels":{}}' >/dev/null

# Agent-originated pairing (v2): request, approve, retrieve credential.
REQUEST_SECRET="request-secret-$(openssl rand -hex 12)"
REQUEST=$(curl -fsS -X POST "$URL/api/agent/v2/pairing-requests" -H 'Content-Type: application/json' --data "{\"installation_id\":\"journey-agent\",\"request_secret\":\"$REQUEST_SECRET\",\"hostname\":\"journey-host\",\"platform\":\"linux/amd64\",\"agent_version\":\"test\"}")
REQUEST_ID=$(printf '%s' "$REQUEST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -fsS -b "$TMP/cookies" -X POST "$URL/api/v1/agent-pairing-requests/$REQUEST_ID/approve" -H 'Content-Type: application/json' -H "X-Watchpost-CSRF: $CSRF" --data '{"post_id":"journey-host"}' >/dev/null
ENROLLMENT=$(curl -fsS -X GET "$URL/api/agent/v2/pairing-requests/$REQUEST_ID" -H "Authorization: Bearer $REQUEST_SECRET")
CREDENTIAL=$(printf '%s' "$ENROLLMENT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["credential"])')

SEQ_FILE="$TMP/seq"
printf '1\n' > "$SEQ_FILE"
deliver_batch() {
  python3 - "$URL" "$CREDENTIAL" "$SEQ_FILE" <<'PY'
import json, sys, time, urllib.request
url, credential, seqfile = sys.argv[1], sys.argv[2], sys.argv[3]
start = int(open(seqfile).read())
now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
batch = {"version":1,"post_id":"journey-host","collector_id":"journey-agent","batch_id":"b-%d" % start,"sent_at":now,
  "samples":[
    {"sequence":start,"observed_at":now,"signal":"cpu.percent","value":12.5,"unit":"percent","quality":"good","labels":{}},
    {"sequence":start+1,"observed_at":now,"signal":"memory.percent","value":55.0,"unit":"percent","quality":"good","labels":{}},
    {"sequence":start+2,"observed_at":now,"signal":"disk.percent","value":40.0,"unit":"percent","quality":"good","labels":{}}]}
req = urllib.request.Request(url+"/api/collector/v1/observations", data=json.dumps(batch).encode(),
  headers={"Content-Type":"application/json","Authorization":"Bearer "+credential}, method="POST")
with urllib.request.urlopen(req) as resp:
    assert resp.status == 202, resp.status
open(seqfile,"w").write(str(start+3))
PY
}
deliver_batch

connected=0
for _ in $(seq 1 30); do
  if curl -fsS -b "$TMP/cookies" "$URL/api/v1/agent-connections" 2>/dev/null | python3 -c 'import json,sys; raise SystemExit(0 if any(x["status"] in ("healthy","partial") for x in json.load(sys.stdin)["connections"]) else 1)'; then connected=1; break; fi
  sleep .2
done
[ "$connected" = 1 ] || { echo "agent did not connect" >&2; exit 1; }

kill "$SERVER_PID"; wait "$SERVER_PID" || true; SERVER_PID=
start_server
deliver_batch
sleep 2

FROM=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO=$(date -u -d '1 hour' +%Y-%m-%dT%H:%M:%SZ)
HISTORY=$(curl -fsS -b "$TMP/cookies" "$URL/api/v1/posts/journey-host/history?signal=cpu.percent&from=$FROM&to=$TO")
printf '%s' "$HISTORY" | python3 -c 'import json,sys; points=json.load(sys.stdin)["points"]; assert len(points)>=2, points'
echo "agent host journey passed"