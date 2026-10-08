package sniff

// QUIC Initial decoding is derived from SagerNet/sing-box common/sniff/quic.go
// (GPL-3.0-or-later). It is kept local to avoid pulling the complete proxy
// engine and its dependency graph into a small OpenWrt observer.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	quicDraft29 = 0xff00001d
	quicV1      = 0x00000001
	quicV2      = 0x6b3343cf
)

var (
	quicSaltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1      = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2      = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

type PacketState struct{ fragments []quicFragment }
type quicFragment struct {
	offset  uint64
	payload []byte
}

func quicClientHello(packet []byte, state *PacketState) (string, error) {
	reader := bytes.NewReader(packet)
	first, err := reader.ReadByte()
	if err != nil || first&0x40 == 0 {
		return "", errors.New("invalid QUIC long header")
	}
	var version uint32
	if err = binary.Read(reader, binary.BigEndian, &version); err != nil {
		return "", err
	}
	if version != quicDraft29 && version != quicV1 && version != quicV2 {
		return "", errors.New("unsupported QUIC version")
	}
	packetType := (first & 0x30) >> 4
	if (version == quicV2 && packetType != 1) || (version != quicV2 && packetType != 0) {
		return "", errors.New("not a QUIC Initial")
	}

	dcidLen, err := reader.ReadByte()
	if err != nil || dcidLen == 0 || dcidLen > 20 {
		return "", errors.New("invalid destination connection id")
	}
	dcid := make([]byte, dcidLen)
	if _, err = io.ReadFull(reader, dcid); err != nil {
		return "", err
	}
	scidLen, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if _, err = io.CopyN(io.Discard, reader, int64(scidLen)); err != nil {
		return "", err
	}
	tokenLen, err := readQUICVarint(reader)
	if err != nil {
		return "", err
	}
	if _, err = io.CopyN(io.Discard, reader, int64(tokenLen)); err != nil {
		return "", err
	}
	packetLen, err := readQUICVarint(reader)
	if err != nil {
		return "", err
	}
	headerLen := len(packet) - reader.Len()
	if headerLen+int(packetLen) > len(packet) || reader.Len() < 20 {
		return "", ErrNeedMore
	}

	sampleOffset := headerLen + 4
	sample := packet[sampleOffset : sampleOffset+aes.BlockSize]
	salt, hpLabel, keyLabel, ivLabel := quicLabels(version)
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, salt)
	secret := quicHKDFLabel(initialSecret, "client in", crypto.SHA256.Size())
	hpKey := quicHKDFLabel(secret, hpLabel, 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return "", err
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, sample)

	decoded := append([]byte(nil), packet...)
	decoded[0] ^= mask[0] & 0x0f
	pnLen := int(decoded[0]&0x03) + 1
	if headerLen+pnLen > len(decoded) {
		return "", ErrNeedMore
	}
	for i := 0; i < pnLen; i++ {
		decoded[headerLen+i] ^= mask[i+1]
	}
	var packetNumber uint64
	for _, value := range decoded[headerLen : headerLen+pnLen] {
		packetNumber = packetNumber<<8 | uint64(value)
	}
	aadEnd := headerLen + pnLen
	ciphertextEnd := headerLen + int(packetLen)
	key := quicHKDFLabel(secret, keyLabel, 16)
	iv := quicHKDFLabel(secret, ivLabel, 12)
	aead, err := newQUICAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	plaintext, err := aead.Open(nil, nonce, decoded[aadEnd:ciphertextEnd], decoded[:aadEnd])
	if err != nil {
		return "", err
	}

	fragments, err := quicCryptoFrames(plaintext)
	if err != nil {
		return "", err
	}
	for _, fragment := range fragments {
		if fragment.offset+uint64(len(fragment.payload)) > 64*1024 {
			return "", errors.New("QUIC ClientHello exceeds observation limit")
		}
		duplicate := false
		for _, existing := range state.fragments {
			if existing.offset == fragment.offset {
				duplicate = true
				break
			}
		}
		if !duplicate {
			state.fragments = append(state.fragments, fragment)
		}
	}
	cryptoData := joinQUICFragments(state.fragments)
	if len(cryptoData) == 0 {
		return "", ErrNeedMore
	}
	record := make([]byte, 5, 5+len(cryptoData))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(cryptoData)))
	record = append(record, cryptoData...)
	_, domain, err := tls(record)
	if err != nil {
		return "", err
	}
	state.fragments = nil
	return domain, nil
}

func quicLabels(version uint32) (salt []byte, hp, key, iv string) {
	if version == quicV2 {
		return quicSaltV2, "quicv2 hp", "quicv2 key", "quicv2 iv"
	}
	if version == quicV1 {
		salt = quicSaltV1
	} else {
		salt = quicSaltDraft29
	}
	return salt, "quic hp", "quic key", "quic iv"
}

func quicHKDFLabel(secret []byte, label string, length int) []byte {
	info := make([]byte, 3, 3+6+len(label)+1)
	binary.BigEndian.PutUint16(info, uint16(length))
	info[2] = byte(6 + len(label))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	result := make([]byte, length)
	if n, err := hkdf.Expand(crypto.SHA256.New, secret, info).Read(result); err != nil || n != length {
		panic("invalid QUIC HKDF expansion")
	}
	return result
}

func newQUICAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func readQUICVarint(reader io.ByteReader) (uint64, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	size := 1 << ((first & 0xc0) >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < int(size); i++ {
		next, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value = value<<8 | uint64(next)
	}
	return value, nil
}

func quicCryptoFrames(data []byte) ([]quicFragment, error) {
	reader := bytes.NewReader(data)
	var fragments []quicFragment
	for reader.Len() > 0 {
		typ, err := readQUICVarint(reader)
		if err != nil {
			return nil, err
		}
		switch typ {
		case 0, 1:
			continue
		case 2, 3:
			if err := skipQUICAck(reader, typ == 3); err != nil {
				return nil, err
			}
		case 6:
			offset, err := readQUICVarint(reader)
			if err != nil {
				return nil, err
			}
			length, err := readQUICVarint(reader)
			if err != nil {
				return nil, err
			}
			if length > uint64(reader.Len()) {
				return nil, ErrNeedMore
			}
			payload := make([]byte, length)
			if _, err = io.ReadFull(reader, payload); err != nil {
				return nil, err
			}
			fragments = append(fragments, quicFragment{offset, payload})
		case 0x1c, 0x1d:
			return fragments, ErrNeedMore
		default:
			return nil, errors.New("unsupported QUIC Initial frame")
		}
	}
	return fragments, nil
}

func skipQUICAck(reader *bytes.Reader, ecn bool) error {
	for i := 0; i < 3; i++ {
		if _, err := readQUICVarint(reader); err != nil {
			return err
		}
	}
	ranges, err := readQUICVarint(reader)
	if err != nil {
		return err
	}
	if _, err = readQUICVarint(reader); err != nil {
		return err
	}
	for i := uint64(0); i < ranges; i++ {
		if _, err = readQUICVarint(reader); err != nil {
			return err
		}
		if _, err = readQUICVarint(reader); err != nil {
			return err
		}
	}
	if ecn {
		for i := 0; i < 3; i++ {
			if _, err = readQUICVarint(reader); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinQUICFragments(fragments []quicFragment) []byte {
	var result []byte
	offset := uint64(0)
	for {
		found := false
		for _, fragment := range fragments {
			if fragment.offset == offset && len(fragment.payload) > 0 {
				result = append(result, fragment.payload...)
				offset += uint64(len(fragment.payload))
				found = true
				break
			}
		}
		if !found {
			return result
		}
	}
}
