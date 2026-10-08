package capture

import (
	"testing"

	"golang.org/x/net/bpf"
)

func TestTransportFilter(t *testing.T) {
	raw, err := transportFilter()
	if err != nil {
		t.Fatal(err)
	}
	vmInstructions, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("cannot disassemble filter")
	}
	vm, err := bpf.NewVM(vmInstructions)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		frame    []byte
		accepted bool
	}{
		{"ipv4 tcp", ethernet(0x0800, 9, 6), true},
		{"ipv4 udp", ethernet(0x0800, 9, 17), true},
		{"ipv4 icmp", ethernet(0x0800, 9, 1), false},
		{"ipv6 tcp", ethernet(0x86dd, 6, 6), true},
		{"ipv6 udp", ethernet(0x86dd, 6, 17), true},
		{"arp", ethernet(0x0806, 0, 0), false},
		{"vlan ipv4 udp", vlanEthernet(0x0800, 9, 17), true},
		{"vlan ipv6 tcp", vlanEthernet(0x86dd, 6, 6), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := vm.Run(test.frame)
			if err != nil {
				t.Fatal(err)
			}
			if (result > 0) != test.accepted {
				t.Fatalf("accepted=%v, want %v", result > 0, test.accepted)
			}
		})
	}
}

func ethernet(etherType uint16, protocolOffset int, protocol byte) []byte {
	frame := make([]byte, 80)
	frame[12], frame[13] = byte(etherType>>8), byte(etherType)
	frame[14+protocolOffset] = protocol
	return frame
}
func vlanEthernet(inner uint16, protocolOffset int, protocol byte) []byte {
	frame := make([]byte, 84)
	frame[12], frame[13] = 0x81, 0x00
	frame[16], frame[17] = byte(inner>>8), byte(inner)
	frame[18+protocolOffset] = protocol
	return frame
}
