package mls

import (
	"encoding/binary"
	"errors"
)

// ErrNotPrivateMessage — the bytes are not an MLS 1.0 PrivateMessage whose
// header this can read.
var ErrNotPrivateMessage = errors.New("mls: not a readable PrivateMessage header")

const (
	protocolVersionMLS10  = 1
	wireFormatPrivateMsg  = 2
	privateMessageMinSize = 2 + 2 + 1 + 8
)

// PrivateMessageEpoch reads the epoch from a PrivateMessage's cleartext
// header (RFC 9420 §6.3: version, wire_format, group_id<V>, epoch). It
// decrypts nothing and authenticates nothing: the value is what the bytes
// claim. The one use is telling a message from before this device's leaf
// entered the group apart from one that fails to open, and a relabelled
// epoch there only hides a message, which a server that withholds it can do
// anyway.
func PrivateMessageEpoch(message []byte) (uint64, error) {
	if len(message) < privateMessageMinSize ||
		binary.BigEndian.Uint16(message[0:2]) != protocolVersionMLS10 ||
		binary.BigEndian.Uint16(message[2:4]) != wireFormatPrivateMsg {
		return 0, ErrNotPrivateMessage
	}
	rest := message[4:]
	n, width, ok := readVarint(rest)
	if !ok || uint64(len(rest)-width) < n+8 {
		return 0, ErrNotPrivateMessage
	}
	rest = rest[width+int(n):]
	return binary.BigEndian.Uint64(rest[:8]), nil
}

// readVarint is RFC 9420 §2.1.2's variable-length integer: the top two bits
// of the first byte give the width (1, 2 or 4 bytes), and 0b11 is invalid.
// A value encoded wider than it needs to be is invalid too.
func readVarint(b []byte) (value uint64, width int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	width = 1 << (b[0] >> 6)
	if width > 4 || len(b) < width {
		return 0, 0, false
	}
	value = uint64(b[0] & 0x3f)
	for _, c := range b[1:width] {
		value = value<<8 | uint64(c)
	}
	if (width == 2 && value < 1<<6) || (width == 4 && value < 1<<14) {
		return 0, 0, false
	}
	return value, width, true
}
