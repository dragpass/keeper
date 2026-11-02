// Tests for the Group change-baseline actions (docs/protocol.md "Entry
// value-change tracking"). A baseline is created only from an admitted bound
// token under a current, signed, one-use decision; a refusal returns no record.
// Test values are compared in memory and never printed.

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	baselineDevice  = "55555555-5555-4555-8555-555555555555"
	baselineTokenID = "66666666-6666-4666-8666-666666666666"
	baselineToken   = "BASELINE-TOKEN-FIXTURE"
)

type baselineFixture struct {
	*auditFixture
	handle string
	iv, ct string
	expiry string
}

func newBaselineFixture(t *testing.T) *baselineFixture {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.ChangeBaselineChallenges = NewGroupDisplayChallengeStore()
	if err := f.store.Set(config.Service, config.DeviceID, baselineDevice); err != nil {
		t.Fatal(err)
	}
	gc := legacyContext(f.v)
	handle := f.openWith(t, f.wrapToMe(t, f.pubPEM, gc), gc)
	expiry := "1789000000"
	resp := HandleGroupEncryptBound(f.deps, proto.GroupEncryptBoundRequest{
		GroupHandle: handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TokenExpiry: expiry, PlaintextB64: base64.StdEncoding.EncodeToString([]byte("value-one")),
	})
	if !resp.Success {
		t.Fatalf("bound encrypt failed: %s", resp.ErrorCode)
	}
	data := resp.Data.(proto.GroupEncryptResponseData)
	return &baselineFixture{auditFixture: f, handle: handle, iv: data.IVB64, ct: data.CiphertextB64, expiry: expiry}
}

func (f *baselineFixture) prepareReq() proto.GroupChangeBaselinePrepareRequest {
	return proto.GroupChangeBaselinePrepareRequest{
		GroupHandle: f.handle, Token: baselineToken, OrgID: f.v.OrgID, GroupID: f.v.GroupID,
		DekVersion: f.v.DekVersion, TokenExpiry: f.expiry, IVB64: f.iv, CiphertextB64: f.ct,
		EntryID: trackEntry, TokenID: baselineTokenID, SessionIssuedAtNanos: "123456789",
	}
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A token without authenticated expiry is not an exception to the lv81 ban.
func TestGroupChangeBaselinePrepare_RefusesALegacyTokenAndMintsNoChallenge(t *testing.T) {
	f := newBaselineFixture(t)
	req := f.prepareReq()
	req.TokenExpiry = ""
	wantCode(t, HandleGroupChangeBaselinePrepare(f.deps, rawJSON(t, req)), proto.TokenLegacyRefused)
	if f.deps.ChangeBaselineChallenges.Len() != 0 {
		t.Fatal("a refused prepare left a challenge")
	}
}

func (f *baselineFixture) prepare(t *testing.T) proto.GroupChangeBaselinePrepareResponseData {
	t.Helper()
	resp := HandleGroupChangeBaselinePrepare(f.deps, rawJSON(t, f.prepareReq()))
	if !resp.Success {
		t.Fatalf("prepare refused: %s", resp.ErrorCode)
	}
	return resp.Data.(proto.GroupChangeBaselinePrepareResponseData)
}

func TestGroupChangeBaselinePrepare_CommitsToTheTokenAndEntry(t *testing.T) {
	f := newBaselineFixture(t)
	got := f.prepare(t)
	fp := sha256.Sum256([]byte(baselineToken))
	label, err := f.deps.GroupSessions.LabelOf(f.handle)
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenFingerprint != hex.EncodeToString(fp[:]) || got.GrantDigest != hex.EncodeToString(label.GrantDigest[:]) ||
		got.GroupID != f.v.GroupID || got.DekVersion != f.v.DekVersion || len(got.OperationDigest) != 64 || len(got.Challenge) != 43 {
		t.Fatalf("prepare commitments do not name the token, grant and scope")
	}
	if f.deps.ChangeBaselineChallenges.Len() != 1 || f.deps.GroupDisplayChallenges.Len() != 0 {
		t.Fatal("baseline challenge not held in its own store")
	}
}

func (f *baselineFixture) decision(t *testing.T, p proto.GroupChangeBaselinePrepareResponseData, mutate func(*proto.ChangeBaselineDecision)) proto.ChangeBaselineDecision {
	t.Helper()
	d := proto.ChangeBaselineDecision{
		Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: baselineDevice,
		TokenID: baselineTokenID, SessionIssuedAtNanos: 123456789,
		OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		GrantDigest: p.GrantDigest, EntryID: trackEntry, TokenFingerprint: p.TokenFingerprint,
		OperationDigest: p.OperationDigest,
		IssuedAt:        f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9,
		ServerKeyVersion: 1,
	}
	if mutate != nil {
		mutate(&d)
	}
	d.Signature = f.sign(t, proto.ChangeBaselineDecisionCanonical(d))
	return d
}

func (f *baselineFixture) execute(t *testing.T, d proto.ChangeBaselineDecision) proto.BaseResponse {
	t.Helper()
	return HandleGroupChangeBaselineExecute(f.deps, rawJSON(t, proto.GroupChangeBaselineExecuteRequest{Prepare: f.prepareReq(), Decision: d}))
}

func TestGroupChangeBaselineExecute_SealsTheFirstRecordFromTheToken(t *testing.T) {
	f := newBaselineFixture(t)
	resp := f.execute(t, f.decision(t, f.prepare(t), nil))
	if !resp.Success {
		t.Fatalf("execute refused: %s", resp.ErrorCode)
	}
	data := resp.Data.(proto.GroupChangeBaselineExecuteResponseData)
	if data.ChangeVerdict != "baseline" || data.ChangeRecord.Seq != 1 || data.ChangeRecord.DekVersion != f.v.DekVersion {
		t.Fatalf("verdict %q seq %d, want baseline 1", data.ChangeVerdict, data.ChangeRecord.Seq)
	}
	// The baseline describes the token's value: saving that value again is same.
	prev := data.ChangeRecord
	next := HandleGroupEncryptBoundTracked(f.deps, proto.GroupEncryptBoundTrackedRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TokenExpiry: f.expiry, EntryID: trackEntry, PreviousRecord: &prev,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte("value-one")),
	})
	if !next.Success || next.Data.(proto.GroupEncryptBoundTrackedResponseData).ChangeVerdict != "same" {
		t.Fatal("baseline does not describe the token's value")
	}
}

func TestGroupChangeBaselinePrepare_RefusesAnExpiredTokenAndMintsNoChallenge(t *testing.T) {
	f := newBaselineFixture(t)
	f.clock.unix = 1789000000 // the token's authenticated expiry
	wantCode(t, HandleGroupChangeBaselinePrepare(f.deps, rawJSON(t, f.prepareReq())), proto.TokenExpired)
	if f.deps.ChangeBaselineChallenges.Len() != 0 {
		t.Fatal("a refused prepare left a challenge")
	}
}

// Every refusal returns no record and no verdict, so nothing can be stored.
func TestGroupChangeBaselineExecute_RefusesWithoutCurrentAuthority(t *testing.T) {
	cases := map[string]func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse{
		"unsigned decision": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			d := f.decision(t, p, nil)
			d.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
			return f.execute(t, d)
		},
		"another entry": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			return f.execute(t, f.decision(t, p, func(d *proto.ChangeBaselineDecision) { d.EntryID = boundOther }))
		},
		"another token": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			return f.execute(t, f.decision(t, p, func(d *proto.ChangeBaselineDecision) {
				d.TokenFingerprint = hex.EncodeToString(make([]byte, 31)) + "01"
			}))
		},
		"another account": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			return f.execute(t, f.decision(t, p, func(d *proto.ChangeBaselineDecision) { d.AccountID = boundOther }))
		},
		"another device": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			return f.execute(t, f.decision(t, p, func(d *proto.ChangeBaselineDecision) { d.DeviceID = boundOther }))
		},
		"another session": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			return f.execute(t, f.decision(t, p, func(d *proto.ChangeBaselineDecision) { d.SessionIssuedAtNanos++ }))
		},
		"expired decision": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			d := f.decision(t, p, nil)
			f.clock.unix += 9
			return f.execute(t, d)
		},
		"signed out after prepare": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			d := f.decision(t, p, nil)
			if _, _, err := keychain.SetAccountBinding(f.store, boundOther, "bob", true); err != nil {
				t.Fatal(err)
			}
			return f.execute(t, d)
		},
		"handle closed after prepare": func(t *testing.T, f *baselineFixture, p proto.GroupChangeBaselinePrepareResponseData) proto.BaseResponse {
			d := f.decision(t, p, nil)
			f.deps.GroupSessions.Close(f.handle)
			return f.execute(t, d)
		},
	}
	for name, run := range cases {
		f := newBaselineFixture(t)
		resp := run(t, f, f.prepare(t))
		if resp.Success || resp.Data != nil {
			t.Errorf("%s: baseline was produced without current authority", name)
		}
	}
}

func TestGroupChangeBaselineExecute_ConsumesTheDecisionOnce(t *testing.T) {
	f := newBaselineFixture(t)
	d := f.decision(t, f.prepare(t), nil)
	if resp := f.execute(t, d); !resp.Success {
		t.Fatal("first execute refused")
	}
	if resp := f.execute(t, d); resp.Success {
		t.Fatal("a replayed decision produced a second baseline")
	}
}

func TestGroupChangeBaselineExecute_RefusesATokenThatExpiredAfterPrepare(t *testing.T) {
	f := newBaselineFixture(t)
	p := f.prepare(t)
	f.clock.unix = 1789000000 - 1
	d := f.decision(t, p, nil)
	f.clock.unix = 1789000000
	if resp := f.execute(t, d); resp.Success {
		t.Fatal("a token that expired after prepare produced a baseline")
	}
}
