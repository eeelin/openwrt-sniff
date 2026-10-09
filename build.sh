#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_URL="${SDK_URL:-}"
SDK_DIR="${SDK_DIR:-}"
GOARCH="${GOARCH:-}"
VERSION="${VERSION:-0.6.0}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/.work}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/dist}"

[[ -n "$GOARCH" ]] || { echo 'GOARCH must be amd64 or arm64' >&2; exit 1; }
[[ "$GOARCH" == amd64 || "$GOARCH" == arm64 ]] || { echo "unsupported GOARCH: $GOARCH" >&2; exit 1; }

if [[ -z "$SDK_DIR" ]]; then
	[[ -n "$SDK_URL" ]] || { echo 'set SDK_URL or SDK_DIR' >&2; exit 1; }
	mkdir -p "$WORK_DIR/downloads"
	archive="$WORK_DIR/downloads/$(basename "$SDK_URL")"
	[[ -f "$archive" ]] || curl -fL --retry 3 -o "$archive" "$SDK_URL"
	root="$(tar -tf "$archive" | awk -F/ 'NF&&!seen{print $1;seen=1}')"
	SDK_DIR="$WORK_DIR/$root"
	[[ -d "$SDK_DIR" ]] || tar -xf "$archive" -C "$WORK_DIR"
fi

(cd "$ROOT_DIR/web" && npm ci && npm run build)
mkdir -p "$ROOT_DIR/package/openwrt-sniff/files/usr/bin"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$ROOT_DIR/package/openwrt-sniff/files/usr/bin/openwrt-sniff" "$ROOT_DIR/cmd/openwrt-sniff"

mkdir -p "$SDK_DIR/package/openwrt-sniff"
rsync -a --delete "$ROOT_DIR/package/openwrt-sniff/" "$SDK_DIR/package/openwrt-sniff/"
(cd "$SDK_DIR" && make OPENWRT_SNIFF_VERSION="$VERSION" defconfig && make OPENWRT_SNIFF_VERSION="$VERSION" package/openwrt-sniff/clean package/openwrt-sniff/compile "-j$(nproc)")

mkdir -p "$ARTIFACT_DIR"
find "$ARTIFACT_DIR" -maxdepth 1 -type f -delete
find "$SDK_DIR/bin/packages" -type f \( -name 'openwrt-sniff_*.ipk' -o -name 'openwrt-sniff-*.apk' \) -exec cp {} "$ARTIFACT_DIR/" \;
(cd "$ARTIFACT_DIR" && sha256sum ./*.ipk ./*.apk 2>/dev/null > sha256sums.txt || true)
find "$ARTIFACT_DIR" -maxdepth 1 -type f -print
