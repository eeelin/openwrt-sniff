package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eeelin/openwrt-sniff/internal/flow"
	"github.com/eeelin/openwrt-sniff/internal/nftset"
	"github.com/eeelin/openwrt-sniff/internal/sniff"
	"github.com/gopacket/gopacket/afpacket"
)

type streamState struct {
	next            uint32
	data            []byte
	pending         []tcpSegment
	pendingBytes    int
	touched         time.Time
	done            bool
	initialized     bool
	synSeen         bool
	midstream       bool
	gaps            uint64
	retransmissions uint64
	state           string
	lastError       string
	expectedBytes   int
	synSequence     uint32
}
type tcpSegment struct {
	sequence uint32
	payload  []byte
}
type packetState struct {
	sniff   sniff.PacketState
	touched time.Time
}
type Status struct {
	Capturing     bool               `json:"capturing"`
	Interfaces    []string           `json:"interfaces"`
	LANPrefixes   []string           `json:"lan_prefixes"`
	BPFEnabled    bool               `json:"bpf_enabled"`
	StartedAt     int64              `json:"started_at,omitempty"`
	Errors        map[string]string  `json:"errors,omitempty"`
	Packets       uint64             `json:"packets"`
	Drops         uint64             `json:"drops"`
	QueueFreezes  uint64             `json:"queue_freezes"`
	NFTSetEnabled bool               `json:"nft_set_enabled"`
	NFTSetErrors  map[string]string  `json:"nft_set_errors,omitempty"`
	Diagnostics   Diagnostics        `json:"diagnostics"`
	DebugCapture  DebugCaptureStatus `json:"debug_capture"`
}

type Diagnostics struct {
	DecodeFailures     uint64 `json:"decode_failures"`
	NonLANPackets      uint64 `json:"non_lan_packets"`
	TCPSequenceGaps    uint64 `json:"tcp_sequence_gaps"`
	TCPRetransmissions uint64 `json:"tcp_retransmissions"`
}

type Manager struct {
	mu              sync.Mutex
	interfaces      []string
	prefixes        []netip.Prefix
	maxStream       int
	store           *flow.Store
	matcher         *nftset.Matcher
	cancel          context.CancelFunc
	status          Status
	streams         map[flow.Key]*streamState
	packetStreams   map[flow.Key]*packetState
	packets         uint64
	generation      uint64
	active          int
	received        atomic.Uint64
	drops           atomic.Uint64
	freezes         atomic.Uint64
	decodeFailures  atomic.Uint64
	nonLAN          atomic.Uint64
	sequenceGaps    atomic.Uint64
	retransmissions atomic.Uint64
	debug           debugRecorder
}

func NewManager(interfaces []string, prefixes []netip.Prefix, maxStream int, store *flow.Store, matcher *nftset.Matcher) *Manager {
	return &Manager{interfaces: interfaces, prefixes: prefixes, maxStream: maxStream, store: store, matcher: matcher, streams: make(map[flow.Key]*streamState), packetStreams: make(map[flow.Key]*packetState), status: Status{Interfaces: interfaces}}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return nil
	}
	filter, err := transportFilter()
	if err != nil {
		return fmt.Errorf("assemble BPF filter: %w", err)
	}
	type source struct {
		name   string
		handle *afpacket.TPacket
	}
	var sources []source
	errorsByInterface := make(map[string]string)
	for _, name := range m.interfaces {
		h, openErr := afpacket.NewTPacket(afpacket.OptInterface(name), afpacket.OptFrameSize(2048), afpacket.OptBlockSize(1<<20), afpacket.OptNumBlocks(4), afpacket.OptPollTimeout(250*time.Millisecond), afpacket.OptTPacketVersion(afpacket.TPacketVersion3))
		if openErr == nil {
			openErr = h.SetBPF(filter)
		}
		if openErr != nil {
			if h != nil {
				h.Close()
			}
			errorsByInterface[name] = openErr.Error()
			continue
		}
		sources = append(sources, source{name, h})
	}
	if len(sources) == 0 {
		m.status = Status{Interfaces: m.interfaces, Errors: errorsByInterface}
		return fmt.Errorf("no capture interface could be opened")
	}
	if len(m.prefixes) == 0 {
		m.prefixes = discoverPrefixes(m.interfaces)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.generation++
	generation := m.generation
	m.active = len(sources)
	m.received.Store(0)
	m.drops.Store(0)
	m.freezes.Store(0)
	m.decodeFailures.Store(0)
	m.nonLAN.Store(0)
	m.sequenceGaps.Store(0)
	m.retransmissions.Store(0)
	m.status = Status{Capturing: true, Interfaces: m.interfaces, LANPrefixes: prefixStrings(m.prefixes), BPFEnabled: true, StartedAt: time.Now().UnixMilli(), Errors: errorsByInterface, NFTSetEnabled: m.matcher != nil && m.matcher.Enabled()}
	if m.matcher != nil {
		m.matcher.Refresh(ctx)
		go m.matcher.Run(ctx)
	}
	for _, source := range sources {
		go m.capture(ctx, generation, source.name, source.handle)
	}
	return nil
}

func (m *Manager) Stop() {
	m.debug.Stop()
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.status.Capturing = false
	m.streams = make(map[flow.Key]*streamState)
	m.packetStreams = make(map[flow.Key]*packetState)
	m.mu.Unlock()
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := m.status
	result.Interfaces = append([]string(nil), m.status.Interfaces...)
	result.LANPrefixes = append([]string(nil), m.status.LANPrefixes...)
	if len(m.status.Errors) > 0 {
		result.Errors = make(map[string]string, len(m.status.Errors))
		for name, message := range m.status.Errors {
			result.Errors[name] = message
		}
	}
	result.Packets, result.Drops, result.QueueFreezes = m.received.Load(), m.drops.Load(), m.freezes.Load()
	result.Diagnostics = Diagnostics{DecodeFailures: m.decodeFailures.Load(), NonLANPackets: m.nonLAN.Load(), TCPSequenceGaps: m.sequenceGaps.Load(), TCPRetransmissions: m.retransmissions.Load()}
	result.DebugCapture = m.debug.Status()
	if m.matcher != nil {
		result.NFTSetErrors = m.matcher.Errors()
	}
	return result
}

func (m *Manager) capture(ctx context.Context, generation uint64, name string, h *afpacket.TPacket) {
	defer h.Close()
	defer m.captureFinished(generation)
	statsTicker := time.NewTicker(time.Second)
	defer statsTicker.Stop()
	var lastPackets, lastDrops, lastFreezes uint
	for {
		select {
		case <-ctx.Done():
			m.collectStats(h, &lastPackets, &lastDrops, &lastFreezes)
			return
		case <-statsTicker.C:
			m.collectStats(h, &lastPackets, &lastDrops, &lastFreezes)
		default:
		}
		packet, info, err := h.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			m.setError(name, err.Error())
			return
		}
		m.debug.Record(packet, info)
		m.consume(packet)
	}
}

func (m *Manager) setError(name, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.Errors == nil {
		m.status.Errors = make(map[string]string)
	}
	m.status.Errors[name] = message
}

func (m *Manager) captureFinished(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation == generation {
		m.active--
		if m.active <= 0 {
			m.status.Capturing = false
			m.cancel = nil
		}
	}
}

func (m *Manager) collectStats(h *afpacket.TPacket, lastPackets, lastDrops, lastFreezes *uint) {
	_, stats, err := h.SocketStats()
	if err != nil {
		return
	}
	packets, drops, freezes := stats.Packets(), stats.Drops(), stats.QueueFreezes()
	m.received.Add(uint64(packets - *lastPackets))
	m.drops.Add(uint64(drops - *lastDrops))
	m.freezes.Add(uint64(freezes - *lastFreezes))
	*lastPackets, *lastDrops, *lastFreezes = packets, drops, freezes
}

func (m *Manager) consume(packet []byte) {
	src, dst, proto, sport, dport, seq, flags, payload, ok := decode(packet)
	if !ok {
		m.decodeFailures.Add(1)
		return
	}
	direction, internalType := m.classifyDirection(packet, src, dst)
	if direction == "" {
		m.nonLAN.Add(1)
		return
	}
	rawKey := flow.Key{Source: netip.AddrPortFrom(src, sport), Destination: netip.AddrPortFrom(dst, dport), Network: proto}
	key, forward := rawKey, true
	if proto == 6 {
		key, forward = connectionKey(rawKey, direction)
	}
	m.mu.Lock()
	m.packets++
	if m.packets%512 == 0 {
		m.pruneStreamsLocked(time.Now())
	}
	m.mu.Unlock()
	protocol, domain := "", ""
	diagnostic := flow.Diagnostic{State: "pending"}
	if proto == 17 {
		var sniffErr error
		m.mu.Lock()
		state, retained := m.packetStreams[rawKey]
		if retained {
			protocol, domain, sniffErr = sniff.Packet(sport, dport, payload, &state.sniff)
			diagnostic = packetDiagnostic(protocol, sniffErr)
			state.touched = time.Now()
			if domain != "" {
				delete(m.packetStreams, rawKey)
			}
			m.mu.Unlock()
		} else {
			m.mu.Unlock()
			candidate := &packetState{touched: time.Now()}
			protocol, domain, sniffErr = sniff.Packet(sport, dport, payload, &candidate.sniff)
			diagnostic = packetDiagnostic(protocol, sniffErr)
			if protocol == "quic" && domain == "" {
				m.mu.Lock()
				if _, exists := m.packetStreams[rawKey]; !exists {
					m.packetStreams[rawKey] = candidate
				}
				m.mu.Unlock()
			}
		}
	}
	if proto == 6 {
		m.mu.Lock()
		state := m.streams[rawKey]
		newConnection := flags&0x02 != 0 && flags&0x10 == 0 && (state == nil || !state.synSeen || state.synSequence != seq)
		if newConnection {
			delete(m.streams, rawKey)
			delete(m.streams, reverseKey(rawKey))
			m.store.Reset(key)
			state = nil
		}
		if state == nil {
			state = &streamState{state: "waiting_for_payload"}
			m.streams[rawKey] = state
		}
		if flags&0x02 != 0 {
			state.synSeen = true
			state.synSequence = seq
			if !state.initialized {
				state.initialized = true
				state.next = seq + 1
			}
		}
		if len(payload) > 0 && !state.done && len(state.data) < m.maxStream {
			if !state.initialized {
				state.initialized = true
				state.midstream = true
				state.next = seq
			}
			payloadSequence := seq
			if flags&0x02 != 0 {
				payloadSequence++
			}
			gap, retransmission := state.add(payloadSequence, payload, m.maxStream)
			if retransmission {
				state.retransmissions++
				m.retransmissions.Add(1)
			}
			if gap > 0 {
				state.gaps++
				state.state = "sequence_gap"
				state.lastError = fmt.Sprintf("waiting for %d missing TCP bytes", gap)
				m.sequenceGaps.Add(1)
			}
			var sniffErr error
			if dport == 53 && len(state.data) > 2 {
				protocol, domain, sniffErr = sniff.Packet(sport, dport, state.data[2:], nil)
			} else {
				protocol, domain, sniffErr = sniff.Stream(state.data)
			}
			if protocol != "" {
				state.done = true
				state.state = "identified"
				state.lastError = ""
				state.data = nil
				reverse := m.streams[reverseKey(rawKey)]
				if reverse == nil {
					reverse = &streamState{}
					m.streams[reverseKey(rawKey)] = reverse
				}
				reverse.done = true
				reverse.state = "identified"
				reverse.data = nil
				reverse.pending = nil
				reverse.pendingBytes = 0
				reverse.touched = time.Now()
			} else if len(state.pending) > 0 {
				state.state = "sequence_gap"
			} else {
				switch {
				case errors.Is(sniffErr, sniff.ErrNeedMore):
					state.state = "need_more"
				case state.midstream:
					state.state = "midstream"
				default:
					state.state = "unrecognized_prefix"
				}
				state.lastError = sniffError(sniffErr)
			}
		}
		if len(state.data) >= m.maxStream && !state.done {
			state.state = "stream_limit"
			state.lastError = "flow prefix reached configured stream limit"
		}
		if len(state.data) >= 5 && state.data[0] == 0x16 {
			state.expectedBytes = 5 + int(binary.BigEndian.Uint16(state.data[3:5]))
		}
		closed := flags&(0x01|0x04) != 0
		if closed && !state.done {
			state.state = "closed_unidentified"
		}
		state.touched = time.Now()
		diagnostic = flow.Diagnostic{State: state.state, Error: state.lastError, StreamBytes: len(state.data), ExpectedBytes: state.expectedBytes, TCPSYNSeen: state.synSeen, TCPGapPackets: state.gaps, TCPRetransmissions: state.retransmissions}
		if closed {
			delete(m.streams, rawKey)
			if state.done {
				delete(m.streams, reverseKey(rawKey))
			}
		}
		m.mu.Unlock()
	}
	proxyAddress := dst
	if direction == "inbound" {
		proxyAddress = src
	}
	proxySetMatch := m.matcher != nil && m.matcher.Contains(proxyAddress)
	initiatorKnown := proto == 6 && flags&0x02 != 0 && flags&0x10 == 0
	m.store.Observe(key, len(packet), protocol, domain, direction, internalType, forward, initiatorKnown, proxySetMatch, diagnostic)
}

func connectionKey(key flow.Key, direction string) (flow.Key, bool) {
	if direction == "outbound" {
		return key, true
	}
	if direction == "inbound" {
		return reverseKey(key), false
	}
	if addrPortLess(key.Destination, key.Source) {
		return reverseKey(key), false
	}
	return key, true
}

func reverseKey(key flow.Key) flow.Key {
	return flow.Key{Source: key.Destination, Destination: key.Source, Network: key.Network}
}

func addrPortLess(left, right netip.AddrPort) bool {
	if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
		return comparison < 0
	}
	return left.Port() < right.Port()
}

func (m *Manager) classifyDirection(packet []byte, src, dst netip.Addr) (direction, internalType string) {
	sourceLAN, destinationLAN := m.isLANAddress(src), m.isLANAddress(dst)
	if sourceLAN && (destinationLAN || dst.IsMulticast() || isBroadcast(packet, dst, m.prefixes)) {
		switch {
		case isBroadcast(packet, dst, m.prefixes):
			return "internal", "broadcast"
		case dst.IsMulticast():
			return "internal", "multicast"
		default:
			return "internal", "unicast"
		}
	}
	if sourceLAN {
		return "outbound", ""
	}
	if destinationLAN {
		return "inbound", ""
	}
	return "", ""
}

func isBroadcast(packet []byte, destination netip.Addr, prefixes []netip.Prefix) bool {
	if len(packet) >= 6 && packet[0] == 0xff && packet[1] == 0xff && packet[2] == 0xff && packet[3] == 0xff && packet[4] == 0xff && packet[5] == 0xff {
		return true
	}
	if !destination.Is4() {
		return false
	}
	value := destination.As4()
	if value == [4]byte{255, 255, 255, 255} {
		return true
	}
	destinationValue := binary.BigEndian.Uint32(value[:])
	for _, prefix := range prefixes {
		if !prefix.Addr().Is4() || prefix.Bits() > 30 {
			continue
		}
		address := prefix.Masked().Addr().As4()
		mask := ^uint32(0) << (32 - prefix.Bits())
		if destinationValue == binary.BigEndian.Uint32(address[:])|^mask {
			return true
		}
	}
	return false
}

func (s *streamState) add(sequence uint32, payload []byte, limit int) (gap int32, retransmission bool) {
	if len(payload) == 0 || len(s.data) >= limit {
		return 0, false
	}
	delta := int32(sequence - s.next)
	if delta < 0 {
		retransmission = true
		overlap := int(s.next - sequence)
		if overlap >= len(payload) {
			return 0, true
		}
		sequence = s.next
		payload = payload[overlap:]
		delta = 0
	}
	if delta > 0 {
		remaining := limit - len(s.data) - s.pendingBytes
		if remaining <= 0 {
			return delta, false
		}
		if len(payload) > remaining {
			payload = payload[:remaining]
		}
		for _, segment := range s.pending {
			if sequence >= segment.sequence && sequence+uint32(len(payload)) <= segment.sequence+uint32(len(segment.payload)) {
				return delta, true
			}
		}
		copied := append([]byte(nil), payload...)
		s.pending = append(s.pending, tcpSegment{sequence: sequence, payload: copied})
		s.pendingBytes += len(copied)
		return delta, false
	}
	s.append(payload, limit)
	for {
		index := -1
		for i, segment := range s.pending {
			if int32(segment.sequence-s.next) <= 0 && int32(segment.sequence+uint32(len(segment.payload))-s.next) > 0 {
				index = i
				break
			}
		}
		if index < 0 {
			break
		}
		segment := s.pending[index]
		s.pending = append(s.pending[:index], s.pending[index+1:]...)
		s.pendingBytes -= len(segment.payload)
		overlap := int(s.next - segment.sequence)
		s.append(segment.payload[overlap:], limit)
	}
	return 0, retransmission
}

func (s *streamState) append(payload []byte, limit int) {
	remaining := limit - len(s.data)
	if remaining <= 0 {
		return
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
	}
	s.data = append(s.data, payload...)
	s.next += uint32(len(payload))
}

func packetDiagnostic(protocol string, err error) flow.Diagnostic {
	if protocol != "" {
		return flow.Diagnostic{State: "identified"}
	}
	return flow.Diagnostic{State: "unidentified", Error: sniffError(err)}
}

func sniffError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, sniff.ErrNeedMore) {
		return "waiting for more protocol bytes"
	}
	return err.Error()
}

func (m *Manager) StartDebugCapture(options DebugCaptureOptions) error {
	m.mu.Lock()
	capturing := m.status.Capturing
	m.mu.Unlock()
	if !capturing {
		return errors.New("packet capture is not active")
	}
	return m.debug.Start(options)
}

func (m *Manager) StopDebugCapture()                 { m.debug.Stop() }
func (m *Manager) TakeDebugCapture() ([]byte, error) { return m.debug.Take() }

func (m *Manager) pruneStreamsLocked(now time.Time) {
	cutoff := now.Add(-5 * time.Minute)
	for key, state := range m.streams {
		if state.touched.Before(cutoff) {
			delete(m.streams, key)
		}
	}
	for key, state := range m.packetStreams {
		if state.touched.Before(cutoff) {
			delete(m.packetStreams, key)
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
	for len(m.packetStreams) > 8192 {
		for key := range m.packetStreams {
			delete(m.packetStreams, key)
			break
		}
	}
}

func (m *Manager) isLANAddress(ip netip.Addr) bool {
	for _, prefix := range m.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return len(m.prefixes) == 0 && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func discoverPrefixes(names []string) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	var result []netip.Prefix
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || prefix.Addr().IsLoopback() {
				continue
			}
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			result = append(result, prefix)
		}
	}
	return result
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		result[i] = prefix.String()
	}
	return result
}

func ParsePrefixes(value string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("invalid LAN prefix %q: %w", item, err)
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func decode(b []byte) (src, dst netip.Addr, proto uint8, sport, dport uint16, seq uint32, flags uint8, payload []byte, ok bool) {
	if len(b) < 14 {
		return
	}
	off := 14
	packetEnd := len(b)
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
		totalLength := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if ihl < 20 || totalLength < ihl || len(b) < off+totalLength {
			return
		}
		fragment := binary.BigEndian.Uint16(b[off+6 : off+8])
		if fragment&0x3fff != 0 {
			return
		}
		packetEnd = off + totalLength
		proto = b[off+9]
		src = netip.AddrFrom4([4]byte{b[off+12], b[off+13], b[off+14], b[off+15]})
		dst = netip.AddrFrom4([4]byte{b[off+16], b[off+17], b[off+18], b[off+19]})
		off += ihl
	case 0x86dd:
		if len(b) < off+40 {
			return
		}
		payloadLength := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if payloadLength == 0 || len(b) < off+40+payloadLength {
			return
		}
		packetEnd = off + 40 + payloadLength
		proto = b[off+6]
		var a, d [16]byte
		copy(a[:], b[off+8:off+24])
		copy(d[:], b[off+24:off+40])
		src, dst = netip.AddrFrom16(a), netip.AddrFrom16(d)
		off += 40
	default:
		return
	}
	if packetEnd < off+8 {
		return
	}
	sport, dport = binary.BigEndian.Uint16(b[off:off+2]), binary.BigEndian.Uint16(b[off+2:off+4])
	if proto == 17 {
		udpLength := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		if udpLength < 8 || off+udpLength > packetEnd {
			return
		}
		payload = b[off+8 : off+udpLength]
		ok = true
		return
	}
	if proto != 6 || packetEnd < off+20 {
		return
	}
	seq = binary.BigEndian.Uint32(b[off+4 : off+8])
	hlen := int(b[off+12]>>4) * 4
	flags = b[off+13]
	if hlen < 20 || packetEnd < off+hlen {
		return
	}
	payload = b[off+hlen : packetEnd]
	ok = true
	return
}
