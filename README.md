# openwrt-sniff

An on-demand, passive traffic observer for OpenWrt. It captures a read-only copy
of LAN packets with Linux AF_PACKET, keeps a short in-memory flow window, and
serves a React dashboard from the same Go binary. It does not add TPROXY,
NFQUEUE, or forwarding rules.

## Current P0 scope

- IPv4 and basic IPv6 TCP/UDP decoding
- DNS query/response names, HTTP Host, TLS ClientHello SNI, and QUIC Initial SNI
- classic socket BPF filtering before packets enter userspace
- bounded TCP prefix reassembly (16 KiB per flow by default)
- live WebSocket updates with no persistent storage
- direction-aware flows for inbound, outbound, and LAN communication; LAN flows
  distinguish unicast, multicast, and broadcast traffic
- bidirectional TCP connection correlation with separate sent/received packet
  and byte counters, active/closed lifecycle state, and dashboard filtering
- capture starts and stops from the web page
- automatic LAN prefix discovery and optional explicit IPv4/IPv6 prefixes
- AF_PACKET packet-drop/queue-freeze counters and per-interface capture errors
- optional nftables-set matching to label destinations handled by sing-box
- OpenWrt procd/UCI packaging

## P1 protocol detection

Detection is content-based rather than limited to well-known ports. Supported
protocols are DNS, HTTP, TLS, QUIC, WeChat MMTLS, SSH, RDP, STUN, DTLS, NTP, and BitTorrent
(TCP handshake, UDP tracker, and uTP SYN). Signatures inspect only bounded flow
prefixes and do not retain payloads after classification.

Detection results include their confidence and domain source. TLS and QUIC
ClientHello inspection also reports protocol version, ALPN values, and whether
an ECH extension was offered. DNS A/AAAA responses (including CNAME chains) are
kept in a client-isolated, TTL-bound in-memory cache so later connections can be
annotated with a `dns_inferred` domain when HTTP Host or SNI is unavailable. The
DNS cache is capped at 8192 entries and is never persisted.

WeChat MMTLS detection validates the proprietary `f1.04` record framing and
ClientHello/ServerHello structure rather than relying on ports or Tencent IP
ranges. Direct MMTLS TCP sessions are labeled `longlink`; MMTLS carried in an
HTTP request body (or explicitly advertised by `Upgrade: mmtls`) is labeled
`shortlink`. Payloads remain encrypted and are not retained.

TCP inspection tracks connection boundaries from SYN/FIN/RST, resets reused
five-tuples, and performs bounded out-of-order prefix reassembly. TLS
ClientHello messages may span multiple TLS records, while QUIC CRYPTO fragments
are joined across packets and overlapping retransmissions.

## Built-in diagnostics

Each flow reports its protocol inspection state, buffered/expected bytes,
whether a TCP SYN was observed, and TCP sequence gaps or retransmissions. The
dashboard can also start a 30-second in-memory packet capture globally or for a
selected source/destination. Captures stop at 2 MiB, are never written to disk,
and are cleared after the PCAP file is downloaded.

The diagnostic capture API is:

```text
POST /api/v1/debug/capture/start
POST /api/v1/debug/capture/stop
POST /api/v1/debug/capture.pcap
```

The start request optionally accepts `source`, `destination`, and `port` in a
JSON body. Leaving the body empty captures all TCP/UDP packets already accepted
by sniffd's socket filter.

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
./install.sh --local /tmp/openwrt-sniff_0.10.0-1_x86_64.ipk
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
checksums, enables the service, restarts it, and prints the generated dashboard
login token. The token is stored in `/etc/sniffd.token` with mode `0600`.

```sh
/etc/init.d/sniffd enable
/etc/init.d/sniffd start
logread -e sniffd
cat /etc/sniffd.token
```

To rotate the dashboard token and invalidate every existing session:

```sh
rm /etc/sniffd.token
/etc/init.d/sniffd restart
cat /etc/sniffd.token
```

Configuration is stored in `/etc/config/sniffd`. The default dashboard
listens on port 8088 and capture remains inactive until requested by the UI.

By default, LAN prefixes are discovered from each configured capture interface.
They can be overridden, and dnsmasq-populated nftables sets can be shown as
`代理集合` in the flow table:

```uci
config main 'main'
	list interface 'br-lan'
	list lan_prefix '192.168.1.0/24'
	list lan_prefix 'fd00:1234::/64'
	list nft_set 'inet:fw4:singbox_proxy4'
	list nft_set 'inet:fw4:singbox_proxy6'
```

The nft set syntax is `family:table:set`. Set contents are read every five
seconds using `nft -j`; sniffd never modifies nftables rules or sets. Apply UCI
changes with `/etc/init.d/sniffd restart`.

The build matrix follows `eeelin/openwrt-trafix`: OpenWrt 22.03.5 and 25.12.5,
each for x86-64 and rockchip/armv8. Build with an SDK using:

```sh
GOARCH=amd64 SDK_URL=https://downloads.openwrt.org/.../openwrt-sdk-....tar.xz ./build.sh
```

OpenWrt 22.03 emits an `.ipk`; OpenWrt 25.12 emits an `.apk`.

## Security

The dashboard and every capture API require token authentication. A successful
login creates a signed, 12-hour `HttpOnly` and `SameSite=Strict` session cookie;
the token is not retained by the browser. Login attempts are rate limited,
state-changing requests are restricted to the dashboard origin, and changing
the token invalidates all existing sessions.

Keep port 8088 restricted to trusted LAN zones. HTTP does not protect the token
from other devices able to observe LAN traffic, so use TLS termination at a
trusted reverse proxy when the network is not trusted. Diagnostic PCAP files
contain packet payloads; they are held only in memory, removed after download,
and expire five minutes after capture completes.

## Attribution

The compact protocol signatures and QUIC Initial decoding under
`internal/sniff` are adapted from
[SagerNet/sing-box](https://github.com/SagerNet/sing-box), licensed under
GPL-3.0-or-later. See `THIRD_PARTY_NOTICES.md` for details.
