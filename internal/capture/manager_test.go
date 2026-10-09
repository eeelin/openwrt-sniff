package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/eeelin/openwrt-sniff/internal/flow"
)

func TestTCPDiagnostics(t *testing.T) {
	store := flow.NewStore(16, time.Minute)
	manager := NewManager(nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, 1024, store, nil)
	source := [4]byte{192, 0, 2, 10}
	destination := [4]byte{198, 51, 100, 20}
	manager.consume(tcpFrame(source, destination, 50000, 443, 1000, 0x02, nil))

	clientHelloPrefix := make([]byte, 100)
	clientHelloPrefix[0], clientHelloPrefix[1], clientHelloPrefix[2] = 0x16, 3, 1
	binary.BigEndian.PutUint16(clientHelloPrefix[3:5], 512)
	manager.consume(tcpFrame(source, destination, 50000, 443, 1001, 0x18, clientHelloPrefix))
	flows := store.Snapshot()
	if len(flows) != 1 {
		t.Fatalf("got %d flows", len(flows))
	}
	got := flows[0]
	if !got.TCPSYNSeen || got.SniffState != "need_more" || got.StreamBytes != 100 || got.ExpectedBytes != 517 {
		t.Fatalf("unexpected diagnostic: %+v", got)
	}

	manager.consume(tcpFrame(source, destination, 50000, 443, 1200, 0x18, []byte{1, 2, 3}))
	got = store.Snapshot()[0]
	if got.SniffState != "sequence_gap" || got.TCPGapPackets != 1 || got.SniffError == "" {
		t.Fatalf("gap was not diagnosed: %+v", got)
	}
	if manager.sequenceGaps.Load() != 1 {
		t.Fatal("global gap counter was not updated")
	}
}

func TestTCPOutOfOrderReassembly(t *testing.T) {
	store := flow.NewStore(16, time.Minute)
	manager := NewManager(nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, 1024, store, nil)
	source := [4]byte{192, 0, 2, 10}
	destination := [4]byte{198, 51, 100, 20}
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	manager.consume(tcpFrame(source, destination, 50000, 443, 1000, 0x02, nil))
	manager.consume(tcpFrame(source, destination, 50000, 443, 1011, 0x18, request[10:]))
	if got := store.Snapshot()[0]; got.SniffState != "sequence_gap" {
		t.Fatalf("future segment did not report a gap: %+v", got)
	}
	manager.consume(tcpFrame(source, destination, 50000, 443, 1001, 0x18, request[:10]))
	got := store.Snapshot()[0]
	if got.Protocol != "http" || got.Domain != "example.com" || got.SniffState != "identified" {
		t.Fatalf("out-of-order request was not reassembled: %+v", got)
	}
}

func TestTCPConnectionReuseAndClose(t *testing.T) {
	store := flow.NewStore(16, time.Minute)
	manager := NewManager(nil, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, 1024, store, nil)
	source := [4]byte{192, 0, 2, 10}
	destination := [4]byte{198, 51, 100, 20}
	manager.consume(tcpFrame(source, destination, 50000, 80, 1000, 0x02, nil))
	manager.consume(tcpFrame(source, destination, 50000, 80, 1001, 0x18, []byte("GET / HTTP/1.1\r\nHost: old.example\r\n\r\n")))
	first := store.Snapshot()[0]
	manager.consume(tcpFrame(source, destination, 50000, 80, 1042, 0x11, nil))
	if len(manager.streams) != 0 {
		t.Fatal("closed TCP stream state was retained")
	}

	manager.consume(tcpFrame(source, destination, 50000, 80, 9000, 0x02, nil))
	second := store.Snapshot()[0]
	if second.ID == first.ID || second.Protocol != "" || second.Domain != "" {
		t.Fatalf("reused tuple retained the previous connection: first=%+v second=%+v", first, second)
	}
}

func tcpFrame(source, destination [4]byte, sourcePort, destinationPort uint16, sequence uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 14+20+20+len(payload))
	packet[12], packet[13] = 0x08, 0x00
	ip := packet[14:]
	ip[0], ip[9] = 0x45, 6
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	tcp[12], tcp[13] = 5<<4, flags
	copy(tcp[20:], payload)
	return packet
}
