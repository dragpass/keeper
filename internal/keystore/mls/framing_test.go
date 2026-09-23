package mls

import (
	"encoding/binary"
	"errors"
	"testing"
)

func privateMessageHeader(groupID []byte, lengthPrefix []byte, epoch uint64) []byte {
	out := []byte{0, 1, 0, 2}
	out = append(out, lengthPrefix...)
	out = append(out, groupID...)
	out = binary.BigEndian.AppendUint64(out, epoch)
	return append(out, 1, 0) // content_type, empty authenticated_data
}

func TestPrivateMessageEpochReadsTheCleartextHeader(t *testing.T) {
	short := make([]byte, 16)
	long := make([]byte, 100)
	for _, tc := range []struct {
		name   string
		msg    []byte
		epoch  uint64
		reject bool
	}{
		{"one-byte length", privateMessageHeader(short, []byte{16}, 7), 7, false},
		{"two-byte length", privateMessageHeader(long, []byte{0x40, 100}, 1<<40), 1 << 40, false},
		{"over-long length", privateMessageHeader(short, []byte{0x40, 16}, 7), 0, true},
		{"reserved width", privateMessageHeader(short, []byte{0xc0, 0, 0, 0, 0, 0, 0, 16}, 7), 0, true},
		{"truncated epoch", privateMessageHeader(short, []byte{16}, 7)[:4+1+16+4], 0, true},
		{"public message", append([]byte{0, 1, 0, 1}, privateMessageHeader(short, []byte{16}, 7)[4:]...), 0, true},
		{"another version", append([]byte{0, 2, 0, 2}, privateMessageHeader(short, []byte{16}, 7)[4:]...), 0, true},
		{"empty", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrivateMessageEpoch(tc.msg)
			if tc.reject {
				if !errors.Is(err, ErrNotPrivateMessage) {
					t.Fatalf("got %d, %v; want a refusal", got, err)
				}
				return
			}
			if err != nil || got != tc.epoch {
				t.Fatalf("got %d, %v; want %d", got, err, tc.epoch)
			}
		})
	}
}
