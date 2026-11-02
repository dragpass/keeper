package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/sessions"
)

func TestGroupSessionOpenBindsHandleToExactWrappedGrant(t *testing.T) {
	f := newAuditFixture(t)
	gc := legacyContext(f.v)
	first := f.wrapToMe(t, f.pubPEM, gc)
	second := f.wrapToMe(t, f.pubPEM, gc)
	firstBytes, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := base64.StdEncoding.DecodeString(second)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256(firstBytes)
	secondDigest := sha256.Sum256(secondBytes)
	if firstDigest == secondDigest {
		t.Fatal("independent wrapped grants unexpectedly matched")
	}
	for _, tc := range []struct {
		grant string
		want  [sha256.Size]byte
	}{
		{first, firstDigest},
		{second, secondDigest},
	} {
		handle := f.openWith(t, tc.grant, gc)
		if err := f.deps.GroupSessions.UseLabeled(handle, func(_ []byte, label sessions.Label) error {
			if label.GrantDigest != tc.want {
				t.Errorf("handle grant digest does not match its wrapped grant")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
