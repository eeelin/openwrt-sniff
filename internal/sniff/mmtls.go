package sniff

import (
	"encoding/binary"
	"errors"
)

const mmtlsVersion = "MMTLS f1.04"

// mmtls recognizes a plaintext MMTLS ClientHello or ServerHello. Requiring the
// proprietary version, a self-consistent record/section length, and the hello
// marker keeps ordinary TLS and arbitrary traffic on ports 443/8080 from being
// mislabeled as WeChat.
func mmtls(data []byte) (Result, error) {
	if len(data) < 3 {
		if matchPrefix(data, []byte{0x16, 0xf1, 0x04}) || matchPrefix(data, []byte{0x19, 0xf1, 0x04}) {
			return Result{}, ErrNeedMore
		}
		return Result{}, errors.New("not MMTLS")
	}
	if (data[0] != 0x16 && data[0] != 0x19) || data[1] != 0xf1 || data[2] != 0x04 {
		return Result{}, errors.New("not MMTLS")
	}
	if len(data) < 5 {
		return Result{}, ErrNeedMore
	}
	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLength < 7 {
		return Result{}, errors.New("invalid MMTLS handshake record")
	}
	if len(data) < 5+recordLength {
		return Result{}, ErrNeedMore
	}
	payload := data[5 : 5+recordLength]
	sectionLength := int(binary.BigEndian.Uint32(payload[:4]))
	if sectionLength != recordLength-4 || (payload[4] != 1 && payload[4] != 2) || payload[5] != 0x03 || payload[6] != 0xf1 {
		return Result{}, errors.New("invalid MMTLS hello")
	}
	return Result{Protocol: "mmtls", Application: "wechat", Version: mmtlsVersion, Confidence: "content"}, nil
}
