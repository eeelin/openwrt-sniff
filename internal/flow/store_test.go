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
	first := store.Observe(key, 64, Detection{Protocol: "tls", Domain: "old.example"}, "outbound", "", "active", true, true, false, Diagnostic{})
	<-events
	store.Reset(key)
	closed := <-events
	if closed.Type != "flow.close" || closed.Flow.ID != first.ID {
		t.Fatalf("unexpected close event: %+v", closed)
	}
	second := store.Observe(key, 64, Detection{}, "outbound", "", "active", true, true, false, Diagnostic{})
	if second.ID == first.ID || second.Protocol != "" || second.Domain != "" {
		t.Fatalf("new connection retained old state: %+v", second)
	}
}

func TestProtocolMetadataOverridesInferredDomain(t *testing.T) {
	store := NewStore(4, time.Minute)
	key := Key{Source: netip.MustParseAddrPort("192.0.2.10:50000"), Destination: netip.MustParseAddrPort("198.51.100.20:443"), Network: 6}
	store.Observe(key, 64, Detection{Domain: "dns.example", DomainSource: "dns_inferred"}, "outbound", "", "active", true, true, false, Diagnostic{})
	got := store.Observe(key, 128, Detection{Protocol: "tls", Domain: "sni.example", DomainSource: "tls_sni", Version: "TLS 1.3", ALPN: []string{"h2"}, ECH: true, Confidence: "content"}, "outbound", "", "active", true, false, false, Diagnostic{})
	if got.Protocol != "tls" || got.Domain != "sni.example" || got.DomainSource != "tls_sni" || got.ProtocolVersion != "TLS 1.3" || len(got.ALPN) != 1 || got.ALPN[0] != "h2" || !got.ECH || got.Confidence != "content" {
		t.Fatalf("unexpected structured detection: %+v", got)
	}
}

func TestApplicationAndTransportMetadata(t *testing.T) {
	store := NewStore(10, time.Minute)
	key := Key{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.20:8080"), Network: 6}
	got := store.Observe(key, 64, Detection{Protocol: "mmtls", Application: "wechat", Transport: "longlink", Version: "MMTLS f1.04", Confidence: "content"}, "outbound", "", "active", true, true, false, Diagnostic{})
	if got.Protocol != "mmtls" || got.Application != "wechat" || got.ProtocolTransport != "longlink" || got.ProtocolVersion != "MMTLS f1.04" {
		t.Fatalf("unexpected application metadata: %+v", got)
	}
}
