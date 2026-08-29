#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); GO_BIN=${GO_BIN:-go}; export GO_BIN; cd "$ROOT"
"$GO_BIN" test ./...
"$GO_BIN" test -race ./...
"$GO_BIN" vet ./...
./hardening/spa-gate.sh
"$GO_BIN" test ./internal/ingest -run '^$' -fuzz FuzzObservationValidation -fuzztime "${WATCHPOST_FUZZ_TIME:-5s}"
./packaging/release-smoke.sh
./hardening/host-journey.sh
./hardening/recovery-drill.sh
WATCHPOST_LONG_RUN_SECONDS=${WATCHPOST_LONG_RUN_SECONDS:-30} ./hardening/long-run.sh
echo 'Watchpost complete local hardening gate passed'
