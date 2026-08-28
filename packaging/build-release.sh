#!/bin/sh
set -eu
version=${1:?version required}
epoch=${SOURCE_DATE_EPOCH:-0}
case "$version" in v[0-9]*) ;; *) echo "version must begin with v" >&2; exit 1;; esac
rm -rf dist
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  stem="watchpost-${version}-${os}-${arch}"; name="watchpost${ext}"
  stage=$(mktemp -d); trap 'rm -rf "$stage"' EXIT HUP INT TERM
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$version" -o "$stage/$name" ./cmd/watchpost
  cp LICENSE README.md "$stage/"
  touch -d "@$epoch" "$stage/$name" "$stage/LICENSE" "$stage/README.md"
  if [ "$os" = windows ]; then (cd "$stage" && zip -Xq "$OLDPWD/dist/$stem.zip" "$name" LICENSE README.md); else tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -czf "dist/$stem.tar.gz" "$name" LICENSE README.md; fi
  cp "$stage/$name" "dist/$stem${ext}"
  rm -rf "$stage"; trap - EXIT HUP INT TERM
done
(cd dist && sha256sum watchpost-* > SHA256SUMS)
