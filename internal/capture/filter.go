package capture

import "golang.org/x/net/bpf"

// transportFilter accepts only Ethernet IPv4/IPv6 packets carrying TCP or UDP.
// It supports untagged frames and one 802.1Q/802.1ad VLAN header. Deeper packet
// classification remains in userspace so this filter works on older OpenWrt
// kernels without eBPF or BTF support.
func transportFilter() ([]bpf.RawInstruction, error) {
	instructions := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 7},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8100, SkipTrue: 10},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x88a8, SkipTrue: 9},
		bpf.RetConstant{Val: 0},

		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 18},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 17},
		bpf.RetConstant{Val: 0},

		bpf.LoadAbsolute{Off: 20, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 14},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 13},
		bpf.RetConstant{Val: 0},

		bpf.LoadAbsolute{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 5},
		bpf.RetConstant{Val: 0},

		bpf.LoadAbsolute{Off: 27, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 6},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 5},
		bpf.RetConstant{Val: 0},

		bpf.LoadAbsolute{Off: 24, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 65535},
	}
	return bpf.Assemble(instructions)
}
