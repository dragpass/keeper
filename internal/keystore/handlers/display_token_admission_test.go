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

// Isolated display admits only bound drag tokens: a request without
// token_expiry is a legacy token, and an expired bound token is refused at
// use. Both refusals come before a challenge is minted or a permit is spent.
func TestDisplayPrepareAdmitsOnlyUnexpiredBoundTokens(t *testing.T) {
	cases := []struct {
		name, expiry, code string
		ok                 bool
	}{
		{"legacy", "", proto.TokenLegacyRefused, false},
		{"expired", "1", proto.TokenExpired, false},
		{"never", "never", "", true},
	}
	for _, c := range cases {
		t.Run("group/"+c.name, func(t *testing.T) {
			f, _, handle := groupDisplayDecisionFixture(t)
			gc := legacyContext(f.v)
			req := proto.CurrentGroupDisplayPrepareRequest{
				GroupHandle: handle, Token: "group-token",
				OrgID: gc.OrgID, GroupID: gc.GroupID, DekVersion: gc.DekVersion, TokenExpiry: c.expiry,
				IVB64:                 base64.StdEncoding.EncodeToString(make([]byte, 12)),
				CiphertextB64:         base64.StdEncoding.EncodeToString(make([]byte, 32)),
				FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(testFrameSPKI(t)),
				TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
			}
			before := f.deps.GroupDisplayChallenges.Len()
			assertDisplayAdmission(t, HandleGroupDisplayPrepare(f.deps, payloadOf(t, req)), f.deps, before, c.ok, c.code)
		})
		t.Run("personal/"+c.name, func(t *testing.T) {
			d, req, binding, _, _ := personalDisplayPrepareFixture(t)
			if !HandlePersonalDEKBind(d, binding).Success {
				t.Fatal("provenance fixture bind failed")
			}
			req.TokenExpiry = c.expiry
			assertDisplayAdmission(t, HandlePersonalDisplayPrepare(d, payloadOf(t, req)), d, 0, c.ok, c.code)
		})
		t.Run("audit/"+c.name, func(t *testing.T) {
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
				TokenExpiry: c.expiry,
			}
			assertDisplayAdmission(t, HandleAuditGroupDisplayPrepare(f.deps, payloadOf(t, req)), f.deps, 0, c.ok, c.code)
		})
	}
}

func TestGroupDisplayPrepareRefusesAnotherTokenScope(t *testing.T) {
	f, _, handle := groupDisplayDecisionFixture(t)
	gc := legacyContext(f.v)
	req := proto.CurrentGroupDisplayPrepareRequest{
		GroupHandle: handle, Token: "group-token",
		OrgID: gc.OrgID, GroupID: "99999999-9999-4999-8999-999999999999", DekVersion: gc.DekVersion, TokenExpiry: "never",
		IVB64:                 base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CiphertextB64:         base64.StdEncoding.EncodeToString(make([]byte, 32)),
		FramePublicKeySPKIB64: base64.StdEncoding.EncodeToString(testFrameSPKI(t)),
		TokenID:               "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: "123456789",
	}
	before := f.deps.GroupDisplayChallenges.Len()
	if resp := HandleGroupDisplayPrepare(f.deps, payloadOf(t, req)); resp.Success {
		t.Fatal("a token naming another Group was prepared on this handle")
	}
	if f.deps.GroupDisplayChallenges.Len() != before {
		t.Fatal("refused scope stored a challenge")
	}
}

func assertDisplayAdmission(t *testing.T, resp proto.BaseResponse, d Deps, challengesBefore int, ok bool, code string) {
	t.Helper()
	if ok {
		if !resp.Success {
			t.Fatalf("bound token refused: %s %s", resp.ErrorCode, resp.Error)
		}
		return
	}
	if resp.Success || resp.ErrorCode != code {
		t.Fatalf("display prepare = success %v code %q, want %s", resp.Success, resp.ErrorCode, code)
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
