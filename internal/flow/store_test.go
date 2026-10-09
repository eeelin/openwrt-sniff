package flow

import (
	"net/netip"
	"testing"
	"time"
)

func TestResetPublishesCloseAndStartsNewFlow(t *testing.T) {
	store := NewStore(4, time.Minute)
	events, cancel := store.Subscribe()
	defer cancel()
	key := Key{
		Source:      netip.MustParseAddrPort("192.0.2.10:50000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
		Network:     6,
	}
	first := store.Observe(key, 64, "tls", "old.example", "outbound", "", false, Diagnostic{})
	<-events
	store.Reset(key)
	closed := <-events
	if closed.Type != "flow.close" || closed.Flow.ID != first.ID {
		t.Fatalf("unexpected close event: %+v", closed)
	}
	second := store.Observe(key, 64, "", "", "outbound", "", false, Diagnostic{})
	if second.ID == first.ID || second.Protocol != "" || second.Domain != "" {
		t.Fatalf("new connection retained old state: %+v", second)
	}
}
