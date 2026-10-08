package sniff

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestHTTPHost(t *testing.T) {
	protocol, domain, err := Stream([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil || protocol != "http" || domain != "example.com" {
		t.Fatalf("got %q %q %v", protocol, domain, err)
	}
}

func TestDNS(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	protocol, domain, err := Packet(12345, 53, packet, nil)
	if err != nil || protocol != "dns" || domain != "www.example.com" {
		t.Fatalf("got %q %q %v", protocol, domain, err)
	}
}

func TestPartialHTTP(t *testing.T) {
	_, _, err := Stream([]byte("GET / HTTP/1.1\r\nHost:"))
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
			protocol, _, err := Stream(test.payload)
			if err != nil || protocol != test.protocol {
				t.Fatalf("got protocol=%q err=%v", protocol, err)
			}
		})
	}
}

func TestPartialStreamSignaturesNeedMore(t *testing.T) {
	for _, payload := range [][]byte{[]byte("SS"), []byte("\x13Bit"), {3, 0, 0}} {
		if _, _, err := Stream(payload); !errors.Is(err, ErrNeedMore) {
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
			protocol, _, err := Packet(40000, 40001, test.payload, nil)
			if err != nil || protocol != test.protocol {
				t.Fatalf("got protocol=%q err=%v", protocol, err)
			}
		})
	}
}

func TestContentDetectionDoesNotRequireWellKnownPort(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	protocol, domain, err := Packet(40000, 40001, packet, nil)
	if err != nil || protocol != "dns" || domain != "example.com" {
		t.Fatalf("got protocol=%q domain=%q err=%v", protocol, domain, err)
	}
}

func TestRandomUDPIsNotUTP(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 1 // uTP version nibble without the initial ST_SYN type.
	if protocol, _, err := Packet(40000, 40001, packet, nil); err == nil || protocol != "" {
		t.Fatalf("random UDP misclassified as %q", protocol)
	}
}

func FuzzStreamNoPanic(f *testing.F) {
	f.Add([]byte{0x16, 3, 3, 0, 0})
	f.Add([]byte("SSH-2.0-test\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Stream(data)
	})
}

func FuzzPacketNoPanic(f *testing.F) {
	f.Add(uint16(12345), uint16(443), []byte{0xc0, 0, 0, 0, 1})
	f.Add(uint16(12345), uint16(3478), make([]byte, 20))
	f.Fuzz(func(t *testing.T, source, destination uint16, data []byte) {
		_, _, _ = Packet(source, destination, data, &PacketState{})
	})
}

func TestTLSClientHelloSNI(t *testing.T) {
	name := []byte("example.com")
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
	protocol, domain, err := Stream(record)
	if err != nil || protocol != "tls" || domain != "example.com" {
		t.Fatalf("got %q %q %v", protocol, domain, err)
	}
}
