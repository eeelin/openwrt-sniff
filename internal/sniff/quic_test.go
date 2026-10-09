package sniff

import (
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestQUICFragmentOverlapAndGap(t *testing.T) {
	fragments := addQUICFragment(nil, quicFragment{offset: 4, payload: []byte("efgh")})
	fragments = addQUICFragment(fragments, quicFragment{offset: 0, payload: []byte("abcdef")})
	fragments = addQUICFragment(fragments, quicFragment{offset: 8, payload: []byte("ij")})
	if got := string(joinQUICFragments(fragments)); got != "abcdefghij" {
		t.Fatalf("joined fragments = %q", got)
	}
	fragments = addQUICFragment(fragments, quicFragment{offset: 12, payload: []byte("mn")})
	if got := string(joinQUICFragments(fragments)); got != "abcdefghij" {
		t.Fatalf("join crossed a gap: %q", got)
	}
}

func TestQUICClientHelloSNI(t *testing.T) {
	packet := makeQUICInitial(t, "quic.example.com")
	domain, err := quicClientHello(packet, &PacketState{})
	if err != nil || domain != "quic.example.com" {
		t.Fatalf("got domain=%q err=%v", domain, err)
	}
}

func makeQUICInitial(t *testing.T, serverName string) []byte {
	t.Helper()
	name := []byte(serverName)
	sni := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(sni[:2], uint16(3+len(name)))
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(name)))
	copy(sni[5:], name)
	extensions := make([]byte, 4+len(sni))
	binary.BigEndian.PutUint16(extensions[2:4], uint16(len(sni)))
	copy(extensions[4:], sni)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	plaintext := []byte{6, 0}
	plaintext = append(plaintext, encodeTestVarint(uint64(len(handshake)))...)
	plaintext = append(plaintext, handshake...)
	plaintext = append(plaintext, make([]byte, 32)...)

	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pn := byte(1)
	header := []byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0, 0)
	packetLength := 1 + len(plaintext) + 16
	header = append(header, encodeTestVarint(uint64(packetLength))...)
	pnOffset := len(header)
	header = append(header, pn)
	initial := hkdf.Extract(crypto.SHA256.New, dcid, quicSaltV1)
	secret := quicHKDFLabel(initial, "client in", crypto.SHA256.Size())
	key := quicHKDFLabel(secret, "quic key", 16)
	iv := quicHKDFLabel(secret, "quic iv", 12)
	nonce := append([]byte(nil), iv...)
	nonce[len(nonce)-1] ^= pn
	aead, err := newQUICAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	packet := aead.Seal(append([]byte(nil), header...), nonce, plaintext, header)
	hpKey := quicHKDFLabel(secret, "quic hp", 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatal(err)
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

func encodeTestVarint(value uint64) []byte {
	if value < 64 {
		return []byte{byte(value)}
	}
	result := []byte{0, 0}
	binary.BigEndian.PutUint16(result, uint16(value)|0x4000)
	return result
}
