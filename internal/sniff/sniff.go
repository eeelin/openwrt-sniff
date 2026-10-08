package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

var ErrNeedMore = errors.New("need more data")

func Stream(data []byte) (protocol, domain string, err error) {
	if len(data) == 0 {
		return "", "", ErrNeedMore
	}
	if looksTLS(data) {
		return tls(data)
	}
	if looksHTTP(data) {
		return http(data)
	}
	if matchPrefix(data, []byte("SSH-2.0-")) {
		if !bytes.Contains(data, []byte{'\n'}) {
			return "", "", ErrNeedMore
		}
		return "ssh", "", nil
	}
	if matchPrefix(data, []byte("\x13BitTorrent protocol")) {
		if len(data) < 20 {
			return "", "", ErrNeedMore
		}
		return "bittorrent", "", nil
	}
	if protocol, ok, needMore := detectRDP(data); ok {
		return protocol, "", nil
	} else if needMore {
		return "", "", ErrNeedMore
	}
	return "", "", errors.New("unknown stream protocol")
}

func Packet(srcPort, dstPort uint16, data []byte, state *PacketState) (protocol, domain string, err error) {
	if srcPort == 53 || dstPort == 53 || looksDNSQuery(data) {
		domain, err = dns(data)
		if err == nil || srcPort == 53 || dstPort == 53 {
			return "dns", domain, err
		}
	}
	if looksQUIC(data) || srcPort == 443 || dstPort == 443 {
		if state == nil {
			state = &PacketState{}
		}
		domain, err = quicClientHello(data, state)
		if errors.Is(err, ErrNeedMore) {
			return "quic", "", nil
		}
		if err != nil && looksQUIC(data) {
			return "quic", "", nil
		}
		if err == nil {
			return "quic", domain, nil
		}
	}
	if looksSTUN(data) {
		return "stun", "", nil
	}
	if looksDTLS(data) {
		return "dtls", "", nil
	}
	if looksBitTorrentPacket(data) {
		return "bittorrent", "", nil
	}
	if looksNTP(data) || ((srcPort == 123 || dstPort == 123) && len(data) >= 48) {
		return "ntp", "", nil
	}
	return "", "", errors.New("unknown packet protocol")
}

func looksTLS(data []byte) bool {
	return len(data) > 0 && data[0] == 0x16
}

func looksHTTP(data []byte) bool {
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
		if matchPrefix(data, []byte(method)) {
			return true
		}
	}
	return false
}

func matchPrefix(data, signature []byte) bool {
	compare := len(data)
	if compare > len(signature) {
		compare = len(signature)
	}
	return compare > 0 && bytes.Equal(data[:compare], signature[:compare])
}

func http(data []byte) (string, string, error) {
	s := string(data)
	lineEnd := strings.Index(s, "\r\n")
	if lineEnd < 0 {
		return "", "", ErrNeedMore
	}
	first := s[:lineEnd]
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	valid := false
	for _, method := range methods {
		if strings.HasPrefix(first, method) {
			valid = true
			break
		}
	}
	if !valid {
		return "", "", errors.New("not http")
	}
	headEnd := strings.Index(s, "\r\n\r\n")
	if headEnd < 0 {
		return "", "", ErrNeedMore
	}
	for _, line := range strings.Split(s[lineEnd+2:headEnd], "\r\n") {
		if len(line) >= 5 && strings.EqualFold(line[:5], "host:") {
			host := strings.TrimSpace(line[5:])
			if i := strings.LastIndex(host, ":"); i > 0 {
				host = host[:i]
			}
			return "http", strings.Trim(host, "[]"), nil
		}
	}
	return "http", "", nil
}

func tls(data []byte) (string, string, error) {
	if len(data) < 5 {
		return "", "", ErrNeedMore
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", "", ErrNeedMore
	}
	if len(data) < 44 || data[5] != 1 {
		return "", "", errors.New("not client hello")
	}
	p := 43
	if p >= len(data) {
		return "", "", ErrNeedMore
	}
	p += 1 + int(data[p])
	if p+2 > len(data) {
		return "", "", ErrNeedMore
	}
	p += 2 + int(binary.BigEndian.Uint16(data[p:p+2]))
	if p >= len(data) {
		return "", "", ErrNeedMore
	}
	p += 1 + int(data[p])
	if p+2 > len(data) {
		return "", "", ErrNeedMore
	}
	extLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(data) {
		return "", "", ErrNeedMore
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(data[p : p+2])
		n := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		p += 4
		if p+n > end {
			return "", "", errors.New("invalid tls extension")
		}
		if typ == 0 && n >= 5 {
			q := p + 2
			for q+3 <= p+n {
				nameType := data[q]
				nameLen := int(binary.BigEndian.Uint16(data[q+1 : q+3]))
				q += 3
				if q+nameLen > p+n {
					break
				}
				if nameType == 0 {
					return "tls", string(data[q : q+nameLen]), nil
				}
				q += nameLen
			}
		}
		p += n
	}
	return "tls", "", nil
}

func dns(data []byte) (string, error) {
	if len(data) < 12 {
		return "", ErrNeedMore
	}
	if binary.BigEndian.Uint16(data[4:6]) == 0 {
		return "", errors.New("no question")
	}
	p := 12
	labels := make([]string, 0, 4)
	for {
		if p >= len(data) {
			return "", ErrNeedMore
		}
		n := int(data[p])
		p++
		if n == 0 {
			break
		}
		if n&0xc0 != 0 || n > 63 || p+n > len(data) {
			return "", errors.New("invalid dns name")
		}
		labels = append(labels, string(data[p:p+n]))
		p += n
	}
	return strings.Join(labels, "."), nil
}
