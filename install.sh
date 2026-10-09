#!/bin/sh

set -eu

REPO="${OPENWRT_SNIFF_GITHUB_REPO:-eeelin/openwrt-sniff}"
VERSION='latest'
SNAPSHOT=0
LOCAL_PACKAGE=''
DRY_RUN=0
START_SERVICE=1

log() { printf '[openwrt-sniff/install] %s\n' "$*"; }
fail() { printf '[openwrt-sniff/install] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
Usage: ./install.sh [options]

Download and install a compatible openwrt-sniff package, or install a local
package produced by ./build.sh.

Options:
  --version TAG   Install a specific GitHub release tag (default: latest)
  --snapshot      Install the latest successful build from the main branch
  --local FILE    Install a local .ipk or .apk instead of downloading a release
  --dry-run       Show the selected package without installing it
  --no-start      Install the package without enabling or restarting the service
  -h, --help      Show this help

Environment:
  OPENWRT_SNIFF_GITHUB_REPO  GitHub owner/repository
                             (default: eeelin/openwrt-sniff)

Examples:
  curl -fsSL https://raw.githubusercontent.com/eeelin/openwrt-sniff/main/install.sh | sh
  ./install.sh --version v0.4.0
  ./install.sh --snapshot
  ./install.sh --local /tmp/openwrt-sniff_0.4.0-1_x86_64.ipk
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version)
			[ "$#" -ge 2 ] || fail '--version requires a tag'
			VERSION="$2"; shift 2
			;;
		--local)
			[ "$#" -ge 2 ] || fail '--local requires a package path'
			LOCAL_PACKAGE="$2"; shift 2
			;;
		--snapshot) SNAPSHOT=1; VERSION='snapshot'; shift ;;
		--dry-run) DRY_RUN=1; shift ;;
		--no-start) START_SERVICE=0; shift ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown argument: $1" ;;
	esac
done

machine="$(uname -m)"
case "$machine" in
	x86_64|amd64) target='x86-64'; package_arch='x86_64' ;;
	aarch64|arm64) target='rockchip-armv8'; package_arch='aarch64_generic' ;;
	*) fail "unsupported architecture: $machine (supported: x86_64, aarch64)" ;;
esac

if command -v apk >/dev/null 2>&1; then
	package_manager='apk'
	package_extension='apk'
	openwrt_version='25.12.5'
elif command -v opkg >/dev/null 2>&1; then
	package_manager='opkg'
	package_extension='ipk'
	openwrt_version='22.03.5'
else
	fail 'neither apk nor opkg was found; run this installer on OpenWrt'
fi

install_package() {
	case "$package_manager" in
		apk) apk add --allow-untrusted "$1" ;;
		opkg) opkg install "$1" ;;
	esac
}

finish_install() {
	if [ "$START_SERVICE" = 1 ] && [ -x /etc/init.d/sniffd ]; then
		/etc/init.d/sniffd enable
		/etc/init.d/sniffd restart
	fi
	log 'installation complete; dashboard: http://<router-lan-ip>:8088'
}

if [ -n "$LOCAL_PACKAGE" ]; then
	[ -f "$LOCAL_PACKAGE" ] || fail "local package not found: $LOCAL_PACKAGE"
	case "$LOCAL_PACKAGE" in
		*."$package_extension") ;;
		*) fail "this router uses $package_manager; expected a .$package_extension package" ;;
	esac
	log "architecture: $machine ($target)"
	log "package manager: $package_manager"
	log "local package: $LOCAL_PACKAGE"
	[ "$DRY_RUN" = 0 ] || exit 0
	install_package "$LOCAL_PACKAGE"
	finish_install
	exit 0
fi

if command -v curl >/dev/null 2>&1; then
	fetch_stdout() { curl -fsSL -H 'Accept: application/vnd.github+json' "$1"; }
	download_file() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch_stdout() { wget -qO- "$1"; }
	download_file() { wget -qO "$2" "$1"; }
else
	fail 'curl or wget is required for release installation'
fi

case "$VERSION" in
	latest) api_url="https://api.github.com/repos/$REPO/releases/latest" ;;
	*) api_url="https://api.github.com/repos/$REPO/releases/tags/$VERSION" ;;
esac

log 'querying GitHub release metadata'
release_json="$(fetch_stdout "$api_url")" || fail "unable to query $api_url"
tag="$(printf '%s\n' "$release_json" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "$tag" ] || fail 'release metadata does not contain tag_name'
package_version="${tag#v}"
asset_urls="$(printf '%s\n' "$release_json" | sed -n 's/.*"browser_download_url": *"\([^"]*\)".*/\1/p')"

if [ "$SNAPSHOT" = 1 ]; then
	package_version_pattern='[^/]+'
else
	package_version_pattern="$package_version"
fi
if [ "$package_manager" = apk ]; then
	asset_pattern="(openwrt-${openwrt_version}-${target}-)?openwrt-sniff-${package_version_pattern}-r[0-9]+\\.apk$"
else
	asset_pattern="(openwrt-${openwrt_version}-${target}-)?openwrt-sniff_${package_version_pattern}-[0-9]+_${package_arch}\\.ipk$"
fi
package_url="$(printf '%s\n' "$asset_urls" | grep -E "$asset_pattern" | head -n 1 || true)"
[ -n "$package_url" ] || fail "release $tag has no compatible $package_manager package for $machine"
package_name="${package_url##*/}"

escaped_version="$(printf '%s' "$openwrt_version" | sed 's/\./\\./g')"
checksum_url="$(printf '%s\n' "$asset_urls" | grep -E "/(openwrt-${escaped_version}-${target}-sha256sums|sha256sums)\\.txt$" | head -n 1 || true)"

log "release: $tag"
log "architecture: $machine ($target)"
log "package manager: $package_manager"
log "asset: $package_name"
[ "$DRY_RUN" = 0 ] || exit 0

tmp_dir="$(mktemp -d /tmp/openwrt-sniff-install.XXXXXX)" || fail 'unable to create temporary directory'
trap 'rm -rf "$tmp_dir"' EXIT INT TERM
package_file="$tmp_dir/$package_name"
download_file "$package_url" "$package_file" || fail 'package download failed'

if [ -n "$checksum_url" ] && command -v sha256sum >/dev/null 2>&1; then
	checksum_file="$tmp_dir/sha256sums.txt"
	download_file "$checksum_url" "$checksum_file" || fail 'checksum download failed'
	expected_hash="$(awk -v name="$package_name" 'NF >= 2 { file=$2; sub(/^\*/, "", file); sub(/^\.\//, "", file); if (file == name) { print $1; exit } }' "$checksum_file")"
	[ -n "$expected_hash" ] || fail "checksum list has no entry for $package_name"
	actual_hash="$(sha256sum "$package_file" | awk '{print $1}')"
	[ "$actual_hash" = "$expected_hash" ] || fail 'package checksum verification failed'
	log 'checksum verified'
else
	log 'warning: release checksum could not be verified'
fi

log "installing $tag"
install_package "$package_file"
finish_install
