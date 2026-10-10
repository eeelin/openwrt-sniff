package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrNeedMore = errors.New("need more data")

func Stream(data []byte) (Result, error) {
	if len(data) == 0 {
		return Result{}, ErrNeedMore
	}
	if result, err := mmtls(data); err == nil || errors.Is(err, ErrNeedMore) {
		if err == nil {
			result.Transport = "longlink"
		}
		return result, err
	}
	if looksTLS(data) {
		return tls(data)
	}
	if looksHTTP(data) {
		return http(data)
	}
	if matchPrefix(data, []byte("SSH-2.0-")) {
		if !bytes.Contains(data, []byte{'\n'}) {
			return Result{}, ErrNeedMore
		}
		return Result{Protocol: "ssh", Confidence: "content"}, nil
	}
	if matchPrefix(data, []byte("\x13BitTorrent protocol")) {
		if len(data) < 20 {
			return Result{}, ErrNeedMore
		}
		return Result{Protocol: "bittorrent", Confidence: "content"}, nil
	}
	if protocol, ok, needMore := detectRDP(data); ok {
		return Result{Protocol: protocol, Confidence: "content"}, nil
	} else if needMore {
		return Result{}, ErrNeedMore
	}
	return Result{}, errors.New("unknown stream protocol")
}

func Packet(srcPort, dstPort uint16, data []byte, state *PacketState) (Result, error) {
	if srcPort == 53 || dstPort == 53 || looksDNSQuery(data) {
		message, err := dns(data)
		if err == nil || srcPort == 53 || dstPort == 53 {
			result := Result{Protocol: "dns", Confidence: "content", DNS: message}
			if message != nil {
				result.Domain = message.Question
				result.DomainSource = domainSource(result.Domain, "dns_question")
			}
			return result, err
		}
	}
	if looksQUIC(data) || srcPort == 443 || dstPort == 443 {
		if state == nil {
			state = &PacketState{}
		}
		result, err := quicClientHello(data, state)
		if errors.Is(err, ErrNeedMore) {
			return partialQUICResult(data), nil
		}
		if err != nil && looksQUIC(data) {
			return partialQUICResult(data), nil
		}
		if err == nil {
			return result, nil
		}
	}
	if looksSTUN(data) {
		return Result{Protocol: "stun", Confidence: "content"}, nil
	}
	if looksDTLS(data) {
		return Result{Protocol: "dtls", Version: dtlsVersion(data), Confidence: "content"}, nil
	}
	if looksBitTorrentPacket(data) {
		return Result{Protocol: "bittorrent", Confidence: "content"}, nil
	}
	if looksNTP(data) || ((srcPort == 123 || dstPort == 123) && len(data) >= 48) {
		confidence := "content"
		if !looksNTP(data) {
			confidence = "port"
		}
		return Result{Protocol: "ntp", Confidence: confidence}, nil
	}
	return Result{}, errors.New("unknown packet protocol")
}

func partialQUICResult(data []byte) Result {
	result := Result{Protocol: "quic", Confidence: "content"}
	if len(data) >= 5 {
		result.Version = quicVersion(binary.BigEndian.Uint32(data[1:5]))
	}
	return result
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

func http(data []byte) (Result, error) {
	s := string(data)
	lineEnd := strings.Index(s, "\r\n")
	if lineEnd < 0 {
		return Result{}, ErrNeedMore
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
		return Result{}, errors.New("not http")
	}
	headEnd := strings.Index(s, "\r\n\r\n")
	if headEnd < 0 {
		return Result{}, ErrNeedMore
	}
	result := Result{Protocol: "http", Confidence: "content"}
	upgradeMMTLS := false
	microMessenger := false
	for _, line := range strings.Split(s[lineEnd+2:headEnd], "\r\n") {
		if len(line) >= 5 && strings.EqualFold(line[:5], "host:") {
			host := strings.TrimSpace(line[5:])
			if i := strings.LastIndex(host, ":"); i > 0 {
				host = host[:i]
			}
			result.Domain = strings.Trim(host, "[]")
			result.DomainSource = domainSource(result.Domain, "http_host")
		} else if len(line) >= 8 && strings.EqualFold(line[:8], "upgrade:") && strings.EqualFold(strings.TrimSpace(line[8:]), "mmtls") {
			upgradeMMTLS = true
		} else if len(line) >= 11 && strings.EqualFold(line[:11], "user-agent:") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line[11:])), "micromessenger") {
			microMessenger = true
		}
	}
	body := data[headEnd+4:]
	if detected, err := mmtls(body); err == nil {
		detected.Domain, detected.DomainSource = result.Domain, result.DomainSource
		detected.Transport = "shortlink"
		return detected, nil
	}
	if upgradeMMTLS || microMessenger {
		result.Protocol = "mmtls"
		result.Application = "wechat"
		result.Transport = "shortlink"
		result.Version = mmtlsVersion
	}
	return result, nil
}

func tls(data []byte) (Result, error) {
	var handshake []byte
	for offset := 0; ; {
		if len(data)-offset < 5 {
			return Result{}, ErrNeedMore
		}
		if data[offset] != 0x16 {
			return Result{}, errors.New("not a TLS handshake record")
		}
		recordLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		if len(data)-offset < 5+recordLen {
			return Result{}, ErrNeedMore
		}
		handshake = append(handshake, data[offset+5:offset+5+recordLen]...)
		if len(handshake) >= 4 {
			handshakeLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) >= 4+handshakeLen {
				return tlsClientHello(handshake[:4+handshakeLen])
			}
		}
		offset += 5 + recordLen
		if offset == len(data) {
			return Result{}, ErrNeedMore
		}
	}
}

func tlsClientHello(data []byte) (Result, error) {
	if len(data) < 39 || data[0] != 1 {
		return Result{}, errors.New("not client hello")
	}
	result := Result{Protocol: "tls", Version: tlsVersion(binary.BigEndian.Uint16(data[4:6])), Confidence: "content"}
	p := 38
	if p >= len(data) {
		return Result{}, ErrNeedMore
	}
	p += 1 + int(data[p])
	if p+2 > len(data) {
		return Result{}, ErrNeedMore
	}
	p += 2 + int(binary.BigEndian.Uint16(data[p:p+2]))
	if p >= len(data) {
		return Result{}, ErrNeedMore
	}
	p += 1 + int(data[p])
	if p+2 > len(data) {
		return Result{}, ErrNeedMore
	}
	extLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(data) {
		return Result{}, ErrNeedMore
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(data[p : p+2])
		n := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		p += 4
		if p+n > end {
			return Result{}, errors.New("invalid tls extension")
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
					result.Domain = string(data[q : q+nameLen])
					result.DomainSource = "tls_sni"
					break
				}
				q += nameLen
			}
		} else if typ == 16 {
			result.ALPN = parseALPN(data[p : p+n])
		} else if typ == 43 && n >= 3 {
			length := int(data[p])
			var selected uint16
			for q := p + 1; q+1 < p+n && q < p+1+length; q += 2 {
				version := binary.BigEndian.Uint16(data[q : q+2])
				if tlsVersion(version) != "" && version > selected {
					selected = version
				}
			}
			result.Version = tlsVersion(selected)
		} else if typ == 0xfe0d || typ == 0xffce {
			result.ECH = true
		}
		p += n
	}
	return result, nil
}

func dns(data []byte) (*DNSMessage, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(data)
	if err != nil {
		return nil, ErrNeedMore
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) == 0 {
		return nil, errors.New("no valid DNS question")
	}
	message := &DNSMessage{Response: header.Response, Question: dnsName(questions[0].Name.String())}
	if !header.Response {
		return message, nil
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return message, err
	}
	aliases := map[string]string{}
	for _, answer := range answers {
		if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
			aliases[dnsName(answer.Header.Name.String())] = dnsName(cname.CNAME.String())
		}
	}
	allowed := map[string]bool{message.Question: true}
	for changed := true; changed; {
		changed = false
		for source, target := range aliases {
			if allowed[source] && !allowed[target] {
				allowed[target], changed = true, true
			}
		}
	}
	for _, answer := range answers {
		name := dnsName(answer.Header.Name.String())
		if !allowed[name] {
			continue
		}
		var address netip.Addr
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			address = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			address = netip.AddrFrom16(body.AAAA)
		}
		if address.IsValid() {
			message.Answers = append(message.Answers, DNSAnswer{Name: message.Question, Address: address, TTL: answer.Header.TTL})
		}
	}
	return message, nil
}

func domainSource(domain, source string) string {
	if domain == "" {
		return ""
	}
	return source
}
func dnsName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

func parseALPN(data []byte) []string {
	if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) > len(data)-2 {
		return nil
	}
	var result []string
	for p, end := 2, 2+int(binary.BigEndian.Uint16(data[:2])); p < end; {
		n := int(data[p])
		p++
		if n == 0 || p+n > end {
			return result
		}
		result = append(result, string(data[p:p+n]))
		p += n
	}
	return result
}

func tlsVersion(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return ""
}

func dtlsVersion(data []byte) string {
	if len(data) < 3 {
		return ""
	}
	if data[2] == 0xfd {
		return "DTLS 1.2"
	}
	if data[2] == 0xff {
		return "DTLS 1.0"
	}
	return ""
}
