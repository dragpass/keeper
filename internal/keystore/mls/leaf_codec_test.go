package mls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func encodeLeavesForTest(leaves []Leaf) []byte {
	var out []byte
	out = binary.BigEndian.AppendUint32(out, uint32(len(leaves)))
	for _, l := range leaves {
		out = binary.BigEndian.AppendUint32(out, l.Index)
		for _, f := range [][]byte{l.Identity, l.SignatureKey} {
			out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
			out = append(out, f...)
		}
		if l.Declaration == nil {
			out = append(out, 0)
			continue
		}
		out = append(out, 1)
		out = binary.BigEndian.AppendUint32(out, uint32(len(l.Declaration)))
		out = append(out, l.Declaration...)
	}
	return out
}

func TestDecodeLeaves_KeepsAbsentAndEmptyDeclarationsApart(t *testing.T) {
	in := []Leaf{
		{Index: 1, Identity: []byte("a"), SignatureKey: []byte("k"), Declaration: nil},
		{Index: 2, Identity: []byte("b"), SignatureKey: []byte("k2"), Declaration: []byte{}},
		{Index: 3, Identity: []byte("c"), SignatureKey: []byte("k3"), Declaration: []byte("d")},
	}
	got, err := decodeLeaves(encodeLeavesForTest(in))
	if err != nil || len(got) != 3 {
		t.Fatalf("decode = %d, %v", len(got), err)
	}
	if got[0].Declaration != nil || got[1].Declaration == nil || !bytes.Equal(got[2].Declaration, []byte("d")) {
		t.Fatal("absent, empty and present declarations did not survive the framing")
	}
}

func TestDecodeLeaves_RefusesMalformedFraming(t *testing.T) {
	good := encodeLeavesForTest([]Leaf{{Index: 1, Identity: []byte("a"), SignatureKey: []byte("k"), Declaration: []byte("d")}})
	bad := map[string][]byte{
		"empty":      nil,
		"truncated":  good[:len(good)-1],
		"trailing":   append(append([]byte{}, good...), 0),
		"huge count": binary.BigEndian.AppendUint32(nil, maxLeaves+1),
	}
	presence := append([]byte{}, good...)
	presence[4+4+4+1+4+1] = 2 // the presence byte after index, identity "a", key "k"
	bad["unknown presence byte"] = presence
	for name, buf := range bad {
		if _, err := decodeLeaves(buf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEncodeApprovals_Framing(t *testing.T) {
	got := encodeApprovals([]Leaf{{Identity: []byte("id"), SignatureKey: []byte("key"), Declaration: []byte("decl")}})
	want := []byte{0, 0, 0, 1, 0, 0, 0, 2, 'i', 'd', 0, 0, 0, 3, 'k', 'e', 'y', 0, 0, 0, 4, 'd', 'e', 'c', 'l'}
	if !bytes.Equal(got, want) {
		t.Fatalf("approvals framing = %v", got)
	}
}
