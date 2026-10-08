#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT_DIR/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

printf 'test apk payload\n' >"$work/package.apk"
hash="$(sha256sum "$work/package.apk" | awk '{print $1}')"
printf '%s  openwrt-25.12.5-rockchip-armv8-openwrt-sniff-0.1.0-r1.apk\n' "$hash" >"$work/sha256sums.txt"
cat >"$work/release.json" <<'EOF'
{
  "tag_name": "v0.1.0",
  "assets": [
    {"browser_download_url":"https://example.test/openwrt-25.12.5-rockchip-armv8-sha256sums.txt"},
    {"browser_download_url":"https://example.test/openwrt-25.12.5-rockchip-armv8-openwrt-sniff-0.1.0-r1.apk"}
  ]
}
EOF

cat >"$work/bin/uname" <<'EOF'
#!/bin/sh
echo aarch64
EOF
cat >"$work/bin/apk" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >"$TEST_APK_ARGS"
EOF
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
output=''; last=''
while [ "$#" -gt 0 ]; do
	case "$1" in -o) output="$2"; shift 2 ;; *) last="$1"; shift ;; esac
done
if [ -z "$output" ]; then cat "$TEST_RELEASE_JSON"
elif echo "$last" | grep -q 'sha256sums.txt$'; then cp "$TEST_CHECKSUM" "$output"
else cp "$TEST_PACKAGE" "$output"; fi
EOF
chmod +x "$work/bin/uname" "$work/bin/apk" "$work/bin/curl"

output="$(PATH="$work/bin:$PATH" TEST_APK_ARGS="$work/apk.args" TEST_RELEASE_JSON="$work/release.json" TEST_CHECKSUM="$work/sha256sums.txt" TEST_PACKAGE="$work/package.apk" "$INSTALLER" --no-start)"
[[ "$output" == *'release: v0.1.0'* ]]
[[ "$output" == *'checksum verified'* ]]
grep -Eq '^add --allow-untrusted .*/openwrt-25\.12\.5-rockchip-armv8-openwrt-sniff-0\.1\.0-r1\.apk$' "$work/apk.args"

PATH="$work/bin:$PATH" TEST_APK_ARGS="$work/local.args" "$INSTALLER" --local "$work/package.apk" --no-start >/dev/null
grep -Eq '^add --allow-untrusted .*/package\.apk$' "$work/local.args"

echo 'All installer tests passed.'
