# openwrt-sniff

An on-demand, passive traffic observer for OpenWrt. It captures a read-only copy
of LAN packets with Linux AF_PACKET, keeps a short in-memory flow window, and
serves a React dashboard from the same Go binary. It does not add TPROXY,
NFQUEUE, or forwarding rules.

## Current v0.1 scope

- IPv4 and basic IPv6 TCP/UDP decoding
- DNS query names, HTTP Host, and TLS ClientHello SNI
- QUIC and NTP protocol labels (QUIC SNI is planned)
- bounded TCP prefix reassembly (16 KiB per flow by default)
- live WebSocket updates with no persistent storage
- capture starts and stops from the web page
- OpenWrt procd/UCI packaging

The observer records LAN-originated flows, including traffic later intercepted
by sing-box. Capture only LAN-facing interfaces to avoid counting the sing-box
outbound connection as a second client flow.

## Local development

Requirements: Go 1.24+, Node.js 24+, and Linux for live AF_PACKET capture.

```sh
make frontend
go test ./cmd/... ./internal/... ./web
go run ./cmd/openwrt-sniff -interfaces br-lan
```

Open `http://router-address:8088`, then press **开始观察**. Live capture needs
root or `CAP_NET_RAW`.

## OpenWrt

Install a package already copied to the router:

```sh
chmod +x ./install.sh
./install.sh --local /tmp/openwrt-sniff_0.1.0-1_x86_64.ipk
```

After a GitHub Release has been published, install the latest compatible build:

```sh
curl -fsSL https://raw.githubusercontent.com/eeelin/openwrt-sniff/main/install.sh | sh
```

Install the current development snapshot directly on an OpenWrt device:

```sh
curl -fsSL https://raw.githubusercontent.com/eeelin/openwrt-sniff/main/install.sh | sh -s -- --snapshot
```

The installer detects `apk`/`opkg` and x86-64/aarch64, verifies release
checksums, enables the service, and restarts it.

```sh
/etc/init.d/sniffd enable
/etc/init.d/sniffd start
logread -e sniffd
```

Configuration is stored in `/etc/config/sniffd`. The default dashboard
listens on port 8088 and capture remains inactive until requested by the UI.

The build matrix follows `eeelin/openwrt-trafix`: OpenWrt 22.03.5 and 25.12.5,
each for x86-64 and rockchip/armv8. Build with an SDK using:

```sh
GOARCH=amd64 SDK_URL=https://downloads.openwrt.org/.../openwrt-sdk-....tar.xz ./build.sh
```

OpenWrt 22.03 emits an `.ipk`; OpenWrt 25.12 emits an `.apk`.

## Security

The dashboard exposes observed destinations and domain names. Keep port 8088
restricted to trusted LAN zones. Authentication and TLS termination are not part
of v0.1; use an authenticated reverse proxy if untrusted clients can reach it.
