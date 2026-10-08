# Third-party notices

## SagerNet/sing-box

`internal/sniff/quic.go` contains adapted QUIC Initial packet decoding logic
from `common/sniff/quic.go` in SagerNet/sing-box:

- Source: https://github.com/SagerNet/sing-box
- License: GNU General Public License v3.0 or later
- Changes: reduced to QUIC Draft-29/v1/v2 Client Initial decryption, replaced
  sing-box buffer/context dependencies with Go standard-library equivalents,
  and added bounded fragment state for passive SNI observation.

The complete openwrt-sniff project is distributed under the same
GPL-3.0-or-later terms. The license text is in `LICENSE`.
