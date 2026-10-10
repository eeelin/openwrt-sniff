package sniff

import "net/netip"

type Result struct {
	Protocol     string
	Application  string
	Transport    string
	Domain       string
	DomainSource string
	ALPN         []string
	Version      string
	ECH          bool
	Confidence   string
	DNS          *DNSMessage
}

type DNSMessage struct {
	Response bool
	Question string
	Answers  []DNSAnswer
}

type DNSAnswer struct {
	Name    string
	Address netip.Addr
	TTL     uint32
}
