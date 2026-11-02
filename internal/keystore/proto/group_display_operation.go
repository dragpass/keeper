package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// CurrentGroupDisplayOperation contains the exact bytes Keeper will use for a
// display attempt. Token is the selected ciphertext token, not plaintext.
// The caller validates the token, handle, ciphertext and frame key separately.
type CurrentGroupDisplayOperation struct {
	Challenge          [32]byte
	GroupHandle        [32]byte
	Token              []byte
	TokenAAD           []byte
	IV                 [12]byte
	Ciphertext         []byte
	FramePublicKeySPKI []byte
}

// CurrentGroupDisplayOperationDigest commits to one Keeper handle, selected
// token and receiving frame. The API receives only this SHA-256 digest.
func CurrentGroupDisplayOperationDigest(op CurrentGroupDisplayOperation) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("dragpass.group.display.operation\x00\x01"))
	writeGroupDisplayDigestField(h, op.Challenge[:])
	writeGroupDisplayDigestField(h, op.GroupHandle[:])
	writeGroupDisplayDigestField(h, op.Token)
	writeGroupDisplayDigestField(h, op.TokenAAD)
	writeGroupDisplayDigestField(h, op.IV[:])
	writeGroupDisplayDigestField(h, op.Ciphertext)
	writeGroupDisplayDigestField(h, op.FramePublicKeySPKI)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeGroupDisplayDigestField(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}
