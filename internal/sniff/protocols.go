package sniff

// The compact protocol signatures in this file are adapted from the
// SagerNet/sing-box common/sniff package (GPL-3.0-or-later). They intentionally
// avoid external DPI databases and inspect only the beginning of each flow.

import "encoding/binary"

func looksQUIC(packet []byte) bool {
	if len(packet) < 5 || packet[0]&0xc0 != 0xc0 {
		return false
	}
	return binary.BigEndian.Uint32(packet[1:5]) != 0
}

func looksSTUN(packet []byte) bool {
	if len(packet) < 20 || packet[0]&0xc0 != 0 {
		return false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	return length%4 == 0 && len(packet) >= 20+length && binary.BigEndian.Uint32(packet[4:8]) == 0x2112a442
}

func looksDTLS(packet []byte) bool {
	if len(packet) < 13 {
		return false
	}
	contentType := packet[0]
	validType := contentType == 20 || contentType == 21 || contentType == 22 || contentType == 23 || contentType == 25
	return validType && packet[1] == 0xfe && (packet[2] == 0xff || packet[2] == 0xfd)
}

func looksNTP(packet []byte) bool {
	if len(packet) < 48 {
		return false
	}
	version := packet[0] >> 3 & 7
	mode := packet[0] & 7
	return (version == 3 || version == 4) && mode == 3 && binary.BigEndian.Uint32(packet[4:8]) <= 16<<16 && binary.BigEndian.Uint32(packet[8:12]) <= 16<<16
}

func looksDNSQuery(packet []byte) bool {
	if len(packet) < 12 || packet[2]&0x80 != 0 || packet[2]&0x7e != 0 || packet[3]&0xc0 != 0 || packet[3]&0x0f != 0 {
		return false
	}
	return binary.BigEndian.Uint16(packet[4:6]) > 0 && binary.BigEndian.Uint16(packet[6:8]) == 0 && binary.BigEndian.Uint16(packet[8:10]) == 0
}

func looksBitTorrentPacket(packet []byte) bool {
	if len(packet) >= 16 && binary.BigEndian.Uint64(packet[:8]) == 0x41727101980 && binary.BigEndian.Uint32(packet[8:12]) == 0 {
		return true
	}
	// The first client packet is ST_SYN (type 4). Restricting detection to it
	// avoids treating roughly 2% of arbitrary UDP payloads as uTP.
	if len(packet) < 20 || packet[0]&0x0f != 1 || packet[0]>>4 != 4 {
		return false
	}
	extension := packet[1]
	offset := 20
	for extension != 0 {
		if offset+2 > len(packet) {
			return false
		}
		extension = packet[offset]
		length := int(packet[offset+1])
		if extension > 4 || offset+2+length > len(packet) {
			return false
		}
		offset += 2 + length
	}
	return true
}

func detectRDP(data []byte) (protocol string, ok, needMore bool) {
	const size = 19
	if len(data) < size {
		prefix := []byte{3, 0}
		if (len(data) <= len(prefix) && matchPrefix(data, prefix)) || (len(data) > 2 && data[0] == 3 && data[1] == 0) {
			return "", false, true
		}
		return "", false, false
	}
	valid := data[0] == 3 && data[1] == 0 && binary.BigEndian.Uint16(data[2:4]) == size && data[4] == 14 && data[5] == 0xe0 && data[11] == 1 && data[13] == 8
	return "rdp", valid, false
}
