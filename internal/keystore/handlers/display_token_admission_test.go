package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Without an authenticated-expiry token format, every isolated display
// preparation must refuse before minting a challenge, whatever the scope.
func TestDisplayPrepareRefusesTokensWithoutAuthenticatedExpiry(t *testing.T) {
	t.Run("group", func(t *testing.T) {
		f, _, handle := groupDisplayDecisionFixture(t)
		f.deps.DisplayTokens = nil
		req := proto.CurrentGroupDisplayPrepareRequest{
			GroupHandle: handle, Token: "group-token",
			TokenAADB64:           base64.StdEncoding.EncodeToString(groupDisplayTestAAD(f)),
			IVB64:                 base64.StdEncoding.EncodeToString(make([]byte, 12)),
			CiphertextB64:         base64.StdEncoding.EncodeToString(make([]byte, 32)),
			FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(testFrameSPKI(t)),
			TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
		}
		before := f.deps.GroupDisplayChallenges.Len()
		assertLegacyRefused(t, HandleGroupDisplayPrepare(f.deps, payloadOf(t, req)), f.deps, before)
	})
	t.Run("personal", func(t *testing.T) {
		d, req, binding, _, _ := personalDisplayPrepareFixture(t)
		if !HandlePersonalDEKBind(d, binding).Success {
			t.Fatal("provenance fixture bind failed")
		}
		d.DisplayTokens = nil
		assertLegacyRefused(t, HandlePersonalDisplayPrepare(d, payloadOf(t, req)), d, 0)
	})
	t.Run("audit", func(t *testing.T) {
		f := newAuditFixture(t)
		f.deps.GroupDisplayChallenges = NewGroupDisplayChallengeStore()
		if err := f.store.Set(config.Service, config.DeviceID, "55555555-5555-4555-8555-555555555555"); err != nil {
			t.Fatal(err)
		}
		req := proto.AuditGroupDisplayPrepareRequest{
			GroupHandle: f.handle, Token: "audit-token", IVB64: base64.StdEncoding.EncodeToString(mustHex(t, f.v.IVHex)),
			CiphertextB64:         base64.StdEncoding.EncodeToString(mustHex(t, f.v.CiphertextHex)),
			FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(testFrameSPKI(t)),
			TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
			OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
			TableID: f.v.TableID, TableB64: base64.StdEncoding.EncodeToString(f.table), Permit: f.permit(t, nil),
		}
		assertLegacyRefused(t, HandleAuditGroupDisplayPrepare(f.deps, payloadOf(t, req)), f.deps, 0)
	})
}

func assertLegacyRefused(t *testing.T, resp proto.BaseResponse, d Deps, challengesBefore int) {
	t.Helper()
	if resp.Success || resp.ErrorCode != proto.DisplayTokenLegacyRefused {
		t.Fatalf("display prepare = success %v code %q, want %s", resp.Success, resp.ErrorCode, proto.DisplayTokenLegacyRefused)
	}
	if d.GroupDisplayChallenges != nil && d.GroupDisplayChallenges.Len() != challengesBefore {
		t.Fatal("refused display still stored a challenge")
	}
}

func testFrameSPKI(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}
