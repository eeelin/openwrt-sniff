package sniff

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestHTTPHost(t *testing.T) {
	result, err := Stream([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil || result.Protocol != "http" || result.Domain != "example.com" || result.DomainSource != "http_host" {
		t.Fatalf("got %+v %v", result, err)
	}
}

func TestDNS(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	result, err := Packet(12345, 53, packet, nil)
	if err != nil || result.Protocol != "dns" || result.Domain != "www.example.com" {
		t.Fatalf("got %+v %v", result, err)
	}
}

func TestPartialHTTP(t *testing.T) {
	_, err := Stream([]byte("GET / HTTP/1.1\r\nHost:"))
	if err != ErrNeedMore {
		t.Fatalf("expected ErrNeedMore, got %v", err)
	}
}

func TestStreamProtocols(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		protocol string
	}{
		{"ssh", []byte("SSH-2.0-OpenSSH_9.9\r\n"), "ssh"},
		{"bittorrent", append([]byte("\x13BitTorrent protocol"), make([]byte, 48)...), "bittorrent"},
		{"rdp", []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0}, "rdp"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Stream(test.payload)
			if err != nil || result.Protocol != test.protocol {
				t.Fatalf("got result=%+v err=%v", result, err)
			}
		})
	}
}

func TestPartialStreamSignaturesNeedMore(t *testing.T) {
	for _, payload := range [][]byte{[]byte("SS"), []byte("\x13Bit"), {3, 0, 0}} {
		if _, err := Stream(payload); !errors.Is(err, ErrNeedMore) {
			t.Fatalf("payload %x: expected ErrNeedMore, got %v", payload, err)
		}
	}
}

func TestPacketProtocols(t *testing.T) {
	stun := make([]byte, 20)
	binary.BigEndian.PutUint32(stun[4:8], 0x2112a442)
	dtls := []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ntp := make([]byte, 48)
	ntp[0] = 4<<3 | 3
	tracker := make([]byte, 16)
	binary.BigEndian.PutUint64(tracker[:8], 0x41727101980)
	utp := make([]byte, 20)
	utp[0] = 4<<4 | 1

	tests := []struct {
		name     string
		payload  []byte
		protocol string
	}{
		{"stun", stun, "stun"},
		{"dtls", dtls, "dtls"},
		{"ntp", ntp, "ntp"},
		{"bittorrent tracker", tracker, "bittorrent"},
		{"bittorrent utp", utp, "bittorrent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Packet(40000, 40001, test.payload, nil)
			if err != nil || result.Protocol != test.protocol {
				t.Fatalf("got result=%+v err=%v", result, err)
			}
		})
	}
}

func TestContentDetectionDoesNotRequireWellKnownPort(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	result, err := Packet(40000, 40001, packet, nil)
	if err != nil || result.Protocol != "dns" || result.Domain != "example.com" {
		t.Fatalf("got result=%+v err=%v", result, err)
	}
}

func TestRandomUDPIsNotUTP(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 1 // uTP version nibble without the initial ST_SYN type.
	if result, err := Packet(40000, 40001, packet, nil); err == nil || result.Protocol != "" {
		t.Fatalf("random UDP misclassified as %+v", result)
	}
}

func FuzzStreamNoPanic(f *testing.F) {
	f.Add([]byte{0x16, 3, 3, 0, 0})
	f.Add([]byte("SSH-2.0-test\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Stream(data)
	})
}

func FuzzPacketNoPanic(f *testing.F) {
	f.Add(uint16(12345), uint16(443), []byte{0xc0, 0, 0, 0, 1})
	f.Add(uint16(12345), uint16(3478), make([]byte, 20))
	f.Fuzz(func(t *testing.T, source, destination uint16, data []byte) {
		_, _ = Packet(source, destination, data, &PacketState{})
	})
}

func TestTLSClientHelloSNI(t *testing.T) {
	record := tlsClientHelloRecord("example.com")
	result, err := Stream(record)
	if err != nil || result.Protocol != "tls" || result.Domain != "example.com" {
		t.Fatalf("got %+v %v", result, err)
	}
}

func TestTLSClientHelloAcrossRecords(t *testing.T) {
	handshake := tlsClientHelloRecord("split.example")[5:]
	split := 24
	record := tlsRecord(handshake[:split])
	record = append(record, tlsRecord(handshake[split:])...)
	result, err := Stream(record)
	if err != nil || result.Protocol != "tls" || result.Domain != "split.example" {
		t.Fatalf("got %+v %v", result, err)
	}
}

func TestTLSClientHelloMetadata(t *testing.T) {
	record := tlsClientHelloMetadataRecord("metadata.example")
	result, err := Stream(record)
	if err != nil || result.Version != "TLS 1.3" || len(result.ALPN) != 2 || result.ALPN[0] != "h2" || result.ALPN[1] != "http/1.1" || !result.ECH {
		t.Fatalf("unexpected TLS metadata: result=%+v err=%v", result, err)
	}
}

func TestDNSResponseFollowsCNAME(t *testing.T) {
	question := dnsmessage.MustNewName("www.example.com.")
	canonical := dnsmessage.MustNewName("edge.example.net.")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: question, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := builder.CNAMEResource(dnsmessage.ResourceHeader{Name: question, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.CNAMEResource{CNAME: canonical}); err != nil {
		t.Fatal(err)
	}
	if err := builder.AResource(dnsmessage.ResourceHeader{Name: canonical, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{203, 0, 113, 8}}); err != nil {
		t.Fatal(err)
	}
	packet, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Packet(53, 53000, packet, nil)
	if err != nil || result.DNS == nil || !result.DNS.Response || len(result.DNS.Answers) != 1 || result.DNS.Answers[0].Address.String() != "203.0.113.8" || result.DNS.Answers[0].Name != "www.example.com" {
		t.Fatalf("unexpected DNS response: result=%+v err=%v", result, err)
	}
}

func tlsClientHelloRecord(host string) []byte {
	name := []byte(host)
	sni := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(sni[0:2], uint16(3+len(name)))
	sni[2] = 0
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(name)))
	copy(sni[5:], name)
	extensions := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(extensions[2:4], uint16(len(sni)))
	copy(extensions[4:], sni)
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record
}

func tlsClientHelloMetadataRecord(host string) []byte {
	record := tlsClientHelloRecord(host)
	handshake := append([]byte(nil), record[5:]...)
	extensionsLengthOffset := 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1
	originalLength := int(binary.BigEndian.Uint16(handshake[extensionsLengthOffset : extensionsLengthOffset+2]))
	extensionsStart := extensionsLengthOffset + 2
	extra := []byte{
		0, 16, 0, 14, 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1',
		0, 43, 0, 3, 2, 3, 4,
		0xfe, 0x0d, 0, 0,
	}
	handshake = append(handshake[:extensionsStart+originalLength], append(extra, handshake[extensionsStart+originalLength:]...)...)
	binary.BigEndian.PutUint16(handshake[extensionsLengthOffset:extensionsLengthOffset+2], uint16(originalLength+len(extra)))
	handshakeLength := len(handshake) - 4
	handshake[1], handshake[2], handshake[3] = byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength)
	return tlsRecord(handshake)
}

func tlsRecord(payload []byte) []byte {
	record := []byte{0x16, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	return append(record, payload...)
}
