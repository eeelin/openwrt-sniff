package nftset

import (
	"net/netip"
	"testing"
)

func TestParsePrefixes(t *testing.T) {
	data := []byte(`{"nftables":[{"set":{"elem":["1.2.3.4",{"prefix":{"addr":"10.20.0.0","len":16}},{"elem":{"val":"2001:db8::1","expires":10}}]}}]}`)
	prefixes, err := parsePrefixes(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"1.2.3.4", "10.20.5.6", "2001:db8::1"} {
		parsed := netip.MustParseAddr(address)
		found := false
		for _, prefix := range prefixes {
			if prefix.Contains(parsed) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s not found in %v", address, prefixes)
		}
	}
}

func TestParseSpecs(t *testing.T) {
	specs, err := ParseSpecs("inet:fw4:proxy4, inet:fw4:proxy6")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].Set != "proxy4" {
		t.Fatalf("unexpected specs: %#v", specs)
	}
}

func TestInvalidPrefixLengthIsIgnored(t *testing.T) {
	prefixes, err := parsePrefixes([]byte(`{"nftables":[{"set":{"elem":[{"prefix":{"addr":"1.2.3.4","len":99}}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("unexpected prefixes: %v", prefixes)
	}
}
