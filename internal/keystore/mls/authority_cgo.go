//go:build mls && cgo

// authority_cgo.go — the framing only the linked library speaks: the shape
// section of the collect pass, and the Removes approved back to it.

package mls

import (
	"encoding/binary"
	"errors"
)

// decodeCollected reads dpmls_group_process_collect's framing: the entering
// leaves, then authority::encode_shape, whose last field is the Commit's
// authenticated data. Strict, as decodeLeaves is.
func decodeCollected(buf []byte) ([]Leaf, CommitShape, error) {
	bad := errors.New("mls: commit shape framing is malformed")
	r := leafReader{buf: buf}
	entering, ok := r.leaves()
	if !ok {
		return nil, CommitShape{}, bad
	}
	flag, ok := r.take(1)
	if !ok || flag[0] > 1 {
		return nil, CommitShape{}, bad
	}
	shape := CommitShape{IsCommit: flag[0] == 1}
	if shape.Committer, ok = r.u32(); !ok {
		return nil, CommitShape{}, bad
	}
	if shape.Removed, ok = r.leaves(); !ok {
		return nil, CommitShape{}, bad
	}
	if shape.Added, ok = r.leaves(); !ok {
		return nil, CommitShape{}, bad
	}
	count, ok := r.u32()
	if !ok || count > maxLeaves {
		return nil, CommitShape{}, bad
	}
	for i := uint32(0); i < count; i++ {
		b, ok := r.take(2)
		if !ok {
			return nil, CommitShape{}, bad
		}
		shape.Other = append(shape.Other, binary.BigEndian.Uint16(b))
	}
	if shape.AuthenticatedData, ok = r.prefixed(); !ok {
		return nil, CommitShape{}, bad
	}
	if r.at != len(r.buf) {
		return nil, CommitShape{}, bad
	}
	return entering, shape, nil
}

// encodeRemovals frames leaves the way authority::decode_removals reads them:
// u32 count, then per leaf its u32 index and length-prefixed identity.
func encodeRemovals(leaves []Leaf) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(leaves)))
	for _, l := range leaves {
		out = binary.BigEndian.AppendUint32(out, l.Index)
		out = binary.BigEndian.AppendUint32(out, uint32(len(l.Identity)))
		out = append(out, l.Identity...)
	}
	return out
}
