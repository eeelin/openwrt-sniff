package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/eeelin/openwrt-sniff/internal/flow"
	"github.com/eeelin/openwrt-sniff/internal/sniff"
	"github.com/gopacket/gopacket/afpacket"
)

type streamState struct {
	next    uint32
	data    []byte
	touched time.Time
	done    bool
}
type Status struct {
	Capturing  bool     `json:"capturing"`
	Interfaces []string `json:"interfaces"`
	StartedAt  int64    `json:"started_at,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type Manager struct {
	mu         sync.Mutex
	interfaces []string
	maxStream  int
	store      *flow.Store
	cancel     context.CancelFunc
	status     Status
	streams    map[flow.Key]*streamState
	packets    uint64
}

func NewManager(interfaces []string, maxStream int, store *flow.Store) *Manager {
	return &Manager{interfaces: interfaces, maxStream: maxStream, store: store, streams: make(map[flow.Key]*streamState), status: Status{Interfaces: interfaces}}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.status = Status{Capturing: true, Interfaces: m.interfaces, StartedAt: time.Now().UnixMilli()}
	for _, name := range m.interfaces {
		go m.capture(ctx, name)
	}
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.status.Capturing = false
	m.streams = make(map[flow.Key]*streamState)
	m.mu.Unlock()
}
func (m *Manager) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.status }

func (m *Manager) capture(ctx context.Context, name string) {
	h, err := afpacket.NewTPacket(afpacket.OptInterface(name), afpacket.OptFrameSize(2048), afpacket.OptBlockSize(1<<20), afpacket.OptNumBlocks(4), afpacket.OptPollTimeout(250*time.Millisecond), afpacket.OptTPacketVersion(afpacket.TPacketVersion3))
	if err != nil {
		m.setError(fmt.Sprintf("%s: %v", name, err))
		return
	}
	defer h.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		packet, _, err := h.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			m.setError(fmt.Sprintf("%s: %v", name, err))
			return
		}
		m.consume(packet)
	}
}

func (m *Manager) setError(message string) { m.mu.Lock(); m.status.Error = message; m.mu.Unlock() }

func (m *Manager) consume(packet []byte) {
	src, dst, proto, sport, dport, seq, flags, payload, ok := decode(packet)
	if !ok || !isPrivate(src) {
		return
	}
	key := flow.Key{Source: netip.AddrPortFrom(src, sport), Destination: netip.AddrPortFrom(dst, dport), Network: proto}
	protocol, domain := "", ""
	if proto == 17 {
		protocol, domain, _ = sniff.Packet(sport, dport, payload)
	}
	if proto == 6 && len(payload) > 0 {
		m.mu.Lock()
		m.packets++
		if m.packets%512 == 0 {
			m.pruneStreamsLocked(time.Now())
		}
		state := m.streams[key]
		if state == nil {
			state = &streamState{}
			m.streams[key] = state
		}
		if !state.done && len(state.data) < m.maxStream {
			if len(state.data) == 0 || seq == state.next {
				remaining := m.maxStream - len(state.data)
				if len(payload) > remaining {
					payload = payload[:remaining]
				}
				state.data = append(state.data, payload...)
				state.next = seq + uint32(len(payload))
			}
			if dport == 53 && len(state.data) > 2 {
				protocol, domain, _ = sniff.Packet(sport, dport, state.data[2:])
			} else {
				protocol, domain, _ = sniff.Stream(state.data)
			}
			if protocol != "" {
				state.done = true
				state.data = nil
			}
		}
		state.touched = time.Now()
		m.mu.Unlock()
	}
	_ = flags
	m.store.Observe(key, len(packet), protocol, domain)
}

func (m *Manager) pruneStreamsLocked(now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	for key, state := range m.streams {
		if state.touched.Before(cutoff) {
			delete(m.streams, key)
		}
	}
	for len(m.streams) > 8192 {
		var oldestKey flow.Key
		var oldest time.Time
		for key, state := range m.streams {
			if oldest.IsZero() || state.touched.Before(oldest) {
				oldestKey, oldest = key, state.touched
			}
		}
		delete(m.streams, oldestKey)
	}
}

func isPrivate(ip netip.Addr) bool { return ip.IsPrivate() || ip.IsLinkLocalUnicast() }

func decode(b []byte) (src, dst netip.Addr, proto uint8, sport, dport uint16, seq uint32, flags uint8, payload []byte, ok bool) {
	if len(b) < 14 {
		return
	}
	off := 14
	ether := binary.BigEndian.Uint16(b[12:14])
	if ether == 0x8100 || ether == 0x88a8 {
		if len(b) < 18 {
			return
		}
		ether = binary.BigEndian.Uint16(b[16:18])
		off = 18
	}
	switch ether {
	case 0x0800:
		if len(b) < off+20 {
			return
		}
		ihl := int(b[off]&15) * 4
		if ihl < 20 || len(b) < off+ihl {
			return
		}
		proto = b[off+9]
		src = netip.AddrFrom4([4]byte{b[off+12], b[off+13], b[off+14], b[off+15]})
		dst = netip.AddrFrom4([4]byte{b[off+16], b[off+17], b[off+18], b[off+19]})
		off += ihl
	case 0x86dd:
		if len(b) < off+40 {
			return
		}
		proto = b[off+6]
		var a, d [16]byte
		copy(a[:], b[off+8:off+24])
		copy(d[:], b[off+24:off+40])
		src, dst = netip.AddrFrom16(a), netip.AddrFrom16(d)
		off += 40
	default:
		return
	}
	if len(b) < off+8 {
		return
	}
	sport, dport = binary.BigEndian.Uint16(b[off:off+2]), binary.BigEndian.Uint16(b[off+2:off+4])
	if proto == 17 {
		payload = b[off+8:]
		ok = true
		return
	}
	if proto != 6 || len(b) < off+20 {
		return
	}
	seq = binary.BigEndian.Uint32(b[off+4 : off+8])
	hlen := int(b[off+12]>>4) * 4
	flags = b[off+13]
	if hlen < 20 || len(b) < off+hlen {
		return
	}
	payload = b[off+hlen:]
	ok = true
	return
}
