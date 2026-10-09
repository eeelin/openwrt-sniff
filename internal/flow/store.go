package flow

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Key struct {
	Source, Destination netip.AddrPort
	Network             uint8
}

type Flow struct {
	ID             uint64 `json:"id"`
	FirstSeen      int64  `json:"first_seen"`
	LastSeen       int64  `json:"last_seen"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
	Network        string `json:"network"`
	Protocol       string `json:"protocol,omitempty"`
	Domain         string `json:"domain,omitempty"`
	PacketsSeen    uint64 `json:"packets_seen"`
	BytesSampled   uint64 `json:"bytes_sampled"`
	ProxySetMatch  bool   `json:"proxy_set_match"`
	Classification string `json:"classification"`
	SniffState     string `json:"sniff_state,omitempty"`
	SniffError     string `json:"sniff_error,omitempty"`
	StreamBytes    int    `json:"stream_bytes,omitempty"`
	ExpectedBytes  int    `json:"expected_bytes,omitempty"`
	TCPSYNSeen     bool   `json:"tcp_syn_seen,omitempty"`
	TCPGapPackets  uint64 `json:"tcp_gap_packets,omitempty"`
	TCPRetransmits uint64 `json:"tcp_retransmissions,omitempty"`
}

type Diagnostic struct {
	State, Error                      string
	StreamBytes, ExpectedBytes        int
	TCPSYNSeen                        bool
	TCPGapPackets, TCPRetransmissions uint64
}

type Event struct {
	Type string `json:"type"`
	Flow Flow   `json:"flow"`
}

type Store struct {
	mu      sync.RWMutex
	items   map[Key]*Flow
	order   []Key
	max     int
	window  time.Duration
	nextID  atomic.Uint64
	subs    map[chan Event]struct{}
	dropped atomic.Uint64
}

func NewStore(max int, window time.Duration) *Store {
	return &Store{items: make(map[Key]*Flow), max: max, window: window, subs: make(map[chan Event]struct{})}
}

func (s *Store) Observe(key Key, size int, protocol, domain string, proxySetMatch bool, diagnostic Diagnostic) Flow {
	now := time.Now().UnixMilli()
	s.mu.Lock()
	f, ok := s.items[key]
	eventType := "flow.update"
	if !ok {
		f = &Flow{ID: s.nextID.Add(1), FirstSeen: now, Source: key.Source.String(), Destination: key.Destination.String(), Classification: "pending"}
		if key.Network == 6 {
			f.Network = "tcp"
		} else {
			f.Network = "udp"
		}
		s.items[key] = f
		s.order = append(s.order, key)
		eventType = "flow.open"
	}
	f.LastSeen, f.PacketsSeen, f.BytesSampled = now, f.PacketsSeen+1, f.BytesSampled+uint64(size)
	if protocol != "" {
		f.Protocol = protocol
	}
	if domain != "" {
		f.Domain = domain
	}
	if f.Protocol != "" {
		f.Classification = "identified"
	}
	f.ProxySetMatch = f.ProxySetMatch || proxySetMatch
	if diagnostic.State != "" {
		f.SniffState = diagnostic.State
	}
	f.SniffError = diagnostic.Error
	f.StreamBytes = diagnostic.StreamBytes
	f.ExpectedBytes = diagnostic.ExpectedBytes
	f.TCPSYNSeen = f.TCPSYNSeen || diagnostic.TCPSYNSeen
	f.TCPGapPackets = diagnostic.TCPGapPackets
	f.TCPRetransmits = diagnostic.TCPRetransmissions
	if f.Protocol != "" {
		f.SniffState = "identified"
		f.SniffError = ""
	}
	copyFlow := *f
	s.pruneLocked(now)
	s.publishLocked(Event{Type: eventType, Flow: copyFlow})
	s.mu.Unlock()
	return copyFlow
}

func (s *Store) pruneLocked(now int64) {
	cutoff := now - s.window.Milliseconds()
	for len(s.order) > 0 && (len(s.items) > s.max || s.items[s.order[0]] == nil || s.items[s.order[0]].LastSeen < cutoff) {
		key := s.order[0]
		s.order = s.order[1:]
		if existing := s.items[key]; existing != nil {
			s.publishLocked(Event{Type: "flow.close", Flow: *existing})
		}
		delete(s.items, key)
	}
}

func (s *Store) publishLocked(event Event) {
	for ch := range s.subs {
		select {
		case ch <- event:
		default:
			s.dropped.Add(1)
		}
	}
}

func (s *Store) Snapshot() []Flow {
	s.mu.RLock()
	result := make([]Flow, 0, len(s.items))
	for _, f := range s.items {
		result = append(result, *f)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen > result[j].LastSeen })
	return result
}

func (s *Store) Clear() { s.mu.Lock(); s.items = make(map[Key]*Flow); s.order = nil; s.mu.Unlock() }
func (s *Store) Reset(key Key) {
	s.mu.Lock()
	if existing := s.items[key]; existing != nil {
		s.publishLocked(Event{Type: "flow.close", Flow: *existing})
	}
	delete(s.items, key)
	filtered := s.order[:0]
	for _, existing := range s.order {
		if existing != key {
			filtered = append(filtered, existing)
		}
	}
	s.order = filtered
	s.mu.Unlock()
}
func (s *Store) Dropped() uint64 { return s.dropped.Load() }
func (s *Store) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 128)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
}

func (s *Store) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}
