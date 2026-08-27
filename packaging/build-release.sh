#!/bin/sh
set -eu
version=${1:?version required}
case "$version" in v[0-9]*) ;; *) echo "version must begin with v" >&2; exit 1;; esac
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  name="watchpost-${version}-${os}-${arch}${ext}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w -X main.version=$version" -o "dist/$name" ./cmd/watchpost
done
(cd dist && sha256sum watchpost-* > SHA256SUMS)
