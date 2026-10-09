package capture

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	debugCaptureDuration = 30 * time.Second
	debugCaptureMaxBytes = 2 << 20
)

type DebugCaptureStatus struct {
	Active    bool   `json:"active"`
	StartedAt int64  `json:"started_at,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Bytes     int    `json:"bytes"`
	Packets   int    `json:"packets"`
	MaxBytes  int    `json:"max_bytes"`
	Ready     bool   `json:"ready"`
	Filter    string `json:"filter,omitempty"`
}

type DebugCaptureOptions struct {
	Source      netip.Addr
	Destination netip.Addr
	Port        uint16
}

type debugRecorder struct {
	mu         sync.Mutex
	buffer     bytes.Buffer
	writer     *pcapgo.Writer
	active     bool
	activeFast atomic.Bool
	startedAt  time.Time
	expiresAt  time.Time
	packets    int
	options    DebugCaptureOptions
}

func (r *debugRecorder) Start(options DebugCaptureOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffer.Reset()
	r.writer = pcapgo.NewWriter(&r.buffer)
	if err := r.writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	r.active = true
	r.activeFast.Store(true)
	r.startedAt = time.Now()
	r.expiresAt = r.startedAt.Add(debugCaptureDuration)
	r.packets = 0
	r.options = options
	return nil
}

func (r *debugRecorder) Stop() {
	r.activeFast.Store(false)
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()
}

func (r *debugRecorder) Record(packet []byte, info gopacket.CaptureInfo) {
	if !r.activeFast.Load() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active {
		return
	}
	if time.Now().After(r.expiresAt) {
		r.active = false
		r.activeFast.Store(false)
		return
	}
	if r.options.Source.IsValid() || r.options.Destination.IsValid() || r.options.Port != 0 {
		source, destination, _, sourcePort, destinationPort, _, _, _, ok := decode(packet)
		forward := (!r.options.Source.IsValid() || source == r.options.Source) && (!r.options.Destination.IsValid() || destination == r.options.Destination)
		reverse := (!r.options.Source.IsValid() || destination == r.options.Source) && (!r.options.Destination.IsValid() || source == r.options.Destination)
		if !ok || (!forward && !reverse) || (r.options.Port != 0 && sourcePort != r.options.Port && destinationPort != r.options.Port) {
			return
		}
	}
	if r.buffer.Len()+len(packet)+16 > debugCaptureMaxBytes {
		r.active = false
		r.activeFast.Store(false)
		return
	}
	info.CaptureLength = len(packet)
	if info.Length == 0 {
		info.Length = len(packet)
	}
	if info.Timestamp.IsZero() {
		info.Timestamp = time.Now()
	}
	if r.writer.WritePacket(info, packet) == nil {
		r.packets++
	}
}

func (r *debugRecorder) Status() DebugCaptureStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active && time.Now().After(r.expiresAt) {
		r.active = false
		r.activeFast.Store(false)
	}
	return DebugCaptureStatus{Active: r.active, StartedAt: millis(r.startedAt), ExpiresAt: millis(r.expiresAt), Bytes: r.buffer.Len(), Packets: r.packets, MaxBytes: debugCaptureMaxBytes, Ready: !r.active && r.packets > 0, Filter: debugFilter(r.options)}
}

func (r *debugRecorder) Take() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active && time.Now().After(r.expiresAt) {
		r.active = false
		r.activeFast.Store(false)
	}
	if r.active {
		return nil, errors.New("debug capture is still active")
	}
	r.activeFast.Store(false)
	if r.packets == 0 {
		return nil, errors.New("no debug capture is available")
	}
	result := append([]byte(nil), r.buffer.Bytes()...)
	r.buffer.Reset()
	r.writer = nil
	r.packets = 0
	r.startedAt = time.Time{}
	r.expiresAt = time.Time{}
	r.options = DebugCaptureOptions{}
	return result, nil
}

func debugFilter(options DebugCaptureOptions) string {
	var result string
	if options.Source.IsValid() {
		result = "src " + options.Source.String()
	}
	if options.Destination.IsValid() {
		if result != "" {
			result += " and "
		}
		result += "dst " + options.Destination.String()
	}
	if options.Port != 0 {
		if result != "" {
			result += " and "
		}
		result += fmt.Sprintf("port %d", options.Port)
	}
	return result
}

func millis(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}
