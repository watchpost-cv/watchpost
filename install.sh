#!/bin/sh
# install.sh installs the watchpost binary only. Machine-service configuration
# (systemd unit, dedicated account, /var/lib/watchpost, protected
# configuration) is owned by the Go CLI: `sudo watchpost service install`.
# With --system the binary is installed to /usr/local/bin and the canonical Go
# service installer is invoked; the shell script contains no systemd logic.
# Set WATCHPOST_SKIP_SERVICE_INSTALL=1 to skip the service configuration step
# (headless/non-systemd contexts and install-script smoke tests).
set -eu
system=0
case "${1:-}" in --system) system=1;; --help|-h) echo 'usage: install.sh [--system]'; exit 0;; '') ;; *) echo 'unknown option' >&2; exit 1;; esac
if [ "$system" -eq 1 ]; then [ "$(id -u)" -eq 0 ] || { echo '--system requires root' >&2; exit 1; }; destination=${WATCHPOST_INSTALL_DIR:-/usr/local/bin}
else [ "$(id -u)" -ne 0 ] || { echo 'do not run the per-user install with sudo; use --system' >&2; exit 1; }; destination=${WATCHPOST_INSTALL_DIR:-"$HOME/.local/bin"}; fi
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64;; arm64|aarch64) arch=arm64;; *) echo "unsupported architecture: $arch" >&2; exit 1;; esac
version=${WATCHPOST_VERSION:-latest}; base=${WATCHPOST_RELEASE_BASE:-https://github.com/watchpost-ops/watchpost/releases/download}
[ "$version" != latest ] || { echo 'Set WATCHPOST_VERSION to a released vX.Y.Z version.' >&2; exit 1; }
ext=""; [ "$os" = windows ] && ext=.exe; name="watchpost-${version}-${os}-${arch}${ext}"; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl -fsSLo "$tmp/$name" "$base/$version/$name"; curl -fsSLo "$tmp/SHA256SUMS" "$base/$version/SHA256SUMS"
(cd "$tmp" && grep " $name\$" SHA256SUMS | sha256sum -c -)
mkdir -p "$destination"; install -m 0755 "$tmp/$name" "$destination/watchpost"; echo "Installed $destination/watchpost"
if [ "$system" -eq 1 ] && [ "${WATCHPOST_SKIP_SERVICE_INSTALL:-0}" != 1 ]; then
  if command -v systemctl >/dev/null 2>&1; then
    echo "Configuring the watchpost machine service..."
    "$destination/watchpost" service install
  else
    echo "systemd not found; run 'sudo watchpost service install' on a systemd host to configure the service."
  fi
fi
case ":$PATH:" in *":$destination:"*) ;; *) echo "Add $destination to PATH.";; esac