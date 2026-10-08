# Third-party notices

## SagerNet/sing-box

`internal/sniff/quic.go` and `internal/sniff/protocols.go` contain adapted
protocol detection logic from `common/sniff` in SagerNet/sing-box:

- Source: https://github.com/SagerNet/sing-box
- Source revision: `fe92ab3e78a9bb7d448c155ef6906218e2ca5453`
- License: GNU General Public License v3.0 or later
- Changes: reduced to bounded, passive signatures for DNS, DTLS, NTP, RDP,
  SSH, STUN and BitTorrent; reduced QUIC handling to Draft-29/v1/v2 Client
  Initial decryption; and replaced sing-box buffer/context dependencies with Go
  standard-library equivalents.

The complete openwrt-sniff project is distributed under the same
GPL-3.0-or-later terms. The license text is in `LICENSE`.
