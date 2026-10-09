package capture

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestDebugRecorderLifecycle(t *testing.T) {
	var recorder debugRecorder
	if err := recorder.Start(DebugCaptureOptions{}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 64)
	recorder.Record(packet, gopacket.CaptureInfo{Timestamp: time.Unix(123, 0), CaptureLength: len(packet), Length: len(packet)})
	if status := recorder.Status(); !status.Active || status.Packets != 1 || status.Bytes <= len(packet) {
		t.Fatalf("unexpected active status: %+v", status)
	}
	if _, err := recorder.Take(); err == nil {
		t.Fatal("download succeeded while capture was active")
	}
	recorder.Stop()
	data, err := recorder.Take()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := reader.ReadPacketData()
	if err != nil || len(decoded) != len(packet) {
		t.Fatalf("invalid pcap packet: len=%d err=%v", len(decoded), err)
	}
	if status := recorder.Status(); status.Ready || status.Bytes != 0 {
		t.Fatalf("capture was not cleared: %+v", status)
	}
}

func TestDebugRecorderFlowFilter(t *testing.T) {
	var recorder debugRecorder
	options := DebugCaptureOptions{Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"), Port: 443}
	if err := recorder.Start(options); err != nil {
		t.Fatal(err)
	}
	info := gopacket.CaptureInfo{}
	recorder.Record(tcpFrame([4]byte{192, 0, 2, 99}, [4]byte{198, 51, 100, 20}, 50000, 443, 1, 0x02, nil), info)
	recorder.Record(tcpFrame([4]byte{192, 0, 2, 10}, [4]byte{198, 51, 100, 20}, 50000, 443, 1, 0x02, nil), info)
	recorder.Record(tcpFrame([4]byte{198, 51, 100, 20}, [4]byte{192, 0, 2, 10}, 443, 50000, 1, 0x12, nil), info)
	status := recorder.Status()
	if status.Packets != 2 || status.Filter != "src 192.0.2.10 and dst 198.51.100.20 and port 443" {
		t.Fatalf("unexpected filtered status: %+v", status)
	}
}

func TestDebugRecorderMemoryLimit(t *testing.T) {
	var recorder debugRecorder
	if err := recorder.Start(DebugCaptureOptions{}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	info := gopacket.CaptureInfo{CaptureLength: len(packet), Length: len(packet)}
	for recorder.Status().Active {
		recorder.Record(packet, info)
	}
	status := recorder.Status()
	if status.Bytes > debugCaptureMaxBytes || status.Packets == 0 || !status.Ready {
		t.Fatalf("unexpected bounded status: %+v", status)
	}
}

func TestDebugRecorderExpiresUndownloadedCapture(t *testing.T) {
	var recorder debugRecorder
	if err := recorder.Start(DebugCaptureOptions{}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 64)
	recorder.Record(packet, gopacket.CaptureInfo{})
	recorder.Stop()
	recorder.mu.Lock()
	recorder.readyUntil = time.Now().Add(-time.Second)
	recorder.mu.Unlock()
	status := recorder.Status()
	if status.Ready || status.Bytes != 0 || status.Packets != 0 {
		t.Fatalf("expired capture was retained: %+v", status)
	}
}
