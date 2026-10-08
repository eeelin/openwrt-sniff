package sniff

import (
	"encoding/binary"
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
