package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCurrentGroupDisplayOperationDigestBindsExactBytes(t *testing.T) {
	op := CurrentGroupDisplayOperation{
		Token:              []byte("⠁⠃"),
		TokenAAD:           []byte("authenticated-aad"),
		Ciphertext:         []byte("ciphertext-and-tag"),
		FramePublicKeySPKI: []byte("synthetic-frame-spki"),
	}
	copy(op.Challenge[:], bytes.Repeat([]byte{0x42}, 32))
	copy(op.GroupHandle[:], bytes.Repeat([]byte{0x33}, 32))
	copy(op.IV[:], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	want := "889b78e1a5cfac21d2380827c7e5968ed5c14a15bf8312c71e8a470fea910fa3"
	digest := CurrentGroupDisplayOperationDigest(op)
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("operation digest differs from the fixed vector: got %s", got)
	}
	frameDigest := sha256.Sum256(op.FramePublicKeySPKI)
	if got := hex.EncodeToString(frameDigest[:]); got != "e3a02e9634d69f72c34bb5e6090ef7a56b1c8cb92a31778bdd1343cd114dc4f8" {
		t.Fatalf("frame key digest differs from the fixed vector: got %s", got)
	}
	baseline := CurrentGroupDisplayOperationDigest(op)
	changed := op
	changed.Token = []byte("⠁⠉")
	if CurrentGroupDisplayOperationDigest(changed) == baseline {
		t.Fatal("another selected token reused the operation digest")
	}
	changed = op
	changed.TokenAAD = []byte("changed-aad")
	if CurrentGroupDisplayOperationDigest(changed) == baseline {
		t.Fatal("another authenticated token context reused the operation digest")
	}
	changed = op
	changed.GroupHandle[0]++
	if CurrentGroupDisplayOperationDigest(changed) == baseline {
		t.Fatal("another Group handle reused the operation digest")
	}
	changed = op
	changed.FramePublicKeySPKI = []byte("other-frame-spki")
	if CurrentGroupDisplayOperationDigest(changed) == baseline {
		t.Fatal("another frame key reused the operation digest")
	}
}
