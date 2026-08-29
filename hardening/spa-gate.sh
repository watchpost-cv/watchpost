#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NIFT_BIN=${NIFT_BIN:-nift}
cd "$ROOT/web"
"$NIFT_BIN" build
"$NIFT_BIN" status >/dev/null
cd "$ROOT"
if ! git diff --quiet -- web/dist; then
  echo "operational SPA dist is not reproducible from canonical Nift source" >&2
  git diff --stat -- web/dist >&2 || true
  exit 1
fi
echo "operational SPA regenerates cleanly from canonical Nift source"