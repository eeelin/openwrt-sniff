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
	debugCaptureDuration  = 30 * time.Second
	debugCaptureMaxBytes  = 2 << 20
	debugCaptureRetention = 5 * time.Minute
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
	mu          sync.Mutex
	buffer      bytes.Buffer
	writer      *pcapgo.Writer
	active      bool
	activeFast  atomic.Bool
	startedAt   time.Time
	expiresAt   time.Time
	readyUntil  time.Time
	expiryTimer *time.Timer
	generation  uint64
	packets     int
	options     DebugCaptureOptions
}

func (r *debugRecorder) Start(options DebugCaptureOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation++
	if r.expiryTimer != nil {
		r.expiryTimer.Stop()
		r.expiryTimer = nil
	}
	r.active = false
	r.activeFast.Store(false)
	r.buffer.Reset()
	r.writer = pcapgo.NewWriter(&r.buffer)
	if err := r.writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	r.active = true
	r.activeFast.Store(true)
	r.startedAt = time.Now()
	r.expiresAt = r.startedAt.Add(debugCaptureDuration)
	r.readyUntil = time.Time{}
	r.packets = 0
	r.options = options
	generation := r.generation
	r.expiryTimer = time.AfterFunc(debugCaptureDuration, func() { r.finish(generation) })
	return nil
}

func (r *debugRecorder) Stop() {
	r.activeFast.Store(false)
	r.mu.Lock()
	r.finishLocked(time.Now())
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
		r.finishLocked(time.Now())
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
		r.finishLocked(time.Now())
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
	r.expireLocked(time.Now())
	return DebugCaptureStatus{Active: r.active, StartedAt: millis(r.startedAt), ExpiresAt: millis(r.expiresAt), Bytes: r.buffer.Len(), Packets: r.packets, MaxBytes: debugCaptureMaxBytes, Ready: !r.active && r.packets > 0, Filter: debugFilter(r.options)}
}

func (r *debugRecorder) expireLocked(now time.Time) {
	if r.active && now.After(r.expiresAt) {
		r.finishLocked(now)
	}
	if !r.active && !r.readyUntil.IsZero() && !now.Before(r.readyUntil) {
		r.clearLocked()
	}
}

func (r *debugRecorder) finish(generation uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation {
		return
	}
	r.finishLocked(time.Now())
}

func (r *debugRecorder) finishLocked(now time.Time) {
	if !r.active {
		return
	}
	r.active = false
	r.activeFast.Store(false)
	if r.packets == 0 {
		r.clearLocked()
		return
	}
	r.readyUntil = now.Add(debugCaptureRetention)
	generation := r.generation
	if r.expiryTimer != nil {
		r.expiryTimer.Stop()
	}
	r.expiryTimer = time.AfterFunc(debugCaptureRetention, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if generation == r.generation && !r.active {
			r.clearLocked()
		}
	})
}

func (r *debugRecorder) Take() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(time.Now())
	if r.active {
		return nil, errors.New("debug capture is still active")
	}
	r.activeFast.Store(false)
	if r.packets == 0 {
		return nil, errors.New("no debug capture is available")
	}
	result := append([]byte(nil), r.buffer.Bytes()...)
	r.clearLocked()
	return result, nil
}

func (r *debugRecorder) clearLocked() {
	if r.expiryTimer != nil {
		r.expiryTimer.Stop()
		r.expiryTimer = nil
	}
	r.buffer.Reset()
	r.writer = nil
	r.packets = 0
	r.startedAt = time.Time{}
	r.expiresAt = time.Time{}
	r.readyUntil = time.Time{}
	r.options = DebugCaptureOptions{}
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
