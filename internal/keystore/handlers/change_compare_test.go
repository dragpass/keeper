// Tests for the server-signed comparison decision (lv83 H1). Test values are
// compared in memory and never printed.

package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/changetrack"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// Without a decision there is no comparison: the verdict is unknown and the
// token and the next record are still sealed.
func TestGroupEncryptBoundTracked_NoDecisionMeansNoVerdict(t *testing.T) {
	f := newBoundGroupFixture(t)
	first := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq("value-one", nil)))
	prev := first.ChangeRecord
	for _, value := range []string{"value-one", "value-two"} {
		got := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq(value, &prev)))
		if got.ChangeVerdict != string(changetrack.VerdictUnknown) || got.CiphertextB64 == "" || got.ChangeRecord.Seq != 2 {
			t.Fatalf("without a decision: verdict %q seq %d, want unknown 2 with a token", got.ChangeVerdict, got.ChangeRecord.Seq)
		}
	}
}

// compareFixture: a labeled current handle, the signed-in binding, a device
// and a server key, as on a real Extension device.
type compareFixture struct {
	*baselineFixture
}

func newCompareFixture(t *testing.T) *compareFixture {
	t.Helper()
	f := newBaselineFixture(t)
	f.deps.ChangeCompareChallenges = NewGroupDisplayChallengeStore()
	return &compareFixture{f}
}

func (f *compareFixture) save(t *testing.T, value string, prev *proto.ChangeRecord, dec *proto.ChangeCompareDecision) proto.GroupEncryptBoundTrackedResponseData {
	t.Helper()
	return trackedData(t, HandleGroupEncryptBoundTracked(f.deps, proto.GroupEncryptBoundTrackedRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		TokenExpiry: f.expiry, EntryID: trackEntry, PreviousRecord: prev, CompareDecision: dec,
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(value)),
	}))
}

func (f *compareFixture) prepare(t *testing.T, prev proto.ChangeRecord) proto.GroupChangeComparePrepareResponseData {
	t.Helper()
	resp := HandleGroupChangeComparePrepare(f.deps, rawJSON(t, proto.GroupChangeComparePrepareRequest{
		GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		EntryID: trackEntry, PreviousRecord: prev, TokenID: baselineTokenID, SessionIssuedAtNanos: "123456789",
	}))
	if !resp.Success {
		t.Fatalf("compare prepare refused: %s", resp.ErrorCode)
	}
	return resp.Data.(proto.GroupChangeComparePrepareResponseData)
}

func (f *compareFixture) decide(t *testing.T, p proto.GroupChangeComparePrepareResponseData, mutate func(*proto.ChangeCompareDecision)) *proto.ChangeCompareDecision {
	t.Helper()
	d := proto.ChangeCompareDecision{
		Challenge: p.Challenge, AccountID: f.v.AccountID, DeviceID: baselineDevice,
		TokenID: baselineTokenID, SessionIssuedAtNanos: 123456789,
		OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
		GrantDigest: p.GrantDigest, EntryID: trackEntry, RecordDigest: p.RecordDigest,
		OperationDigest: p.OperationDigest,
		IssuedAt:        f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9, ServerKeyVersion: 1,
	}
	if mutate != nil {
		mutate(&d)
	}
	d.Signature = f.sign(t, proto.ChangeCompareDecisionCanonical(d))
	return &d
}

func TestGroupEncryptBoundTracked_ComparesUnderAValidDecision(t *testing.T) {
	f := newCompareFixture(t)
	first := f.save(t, "value-one", nil, nil)
	prev := first.ChangeRecord
	same := f.save(t, "value-one", &prev, f.decide(t, f.prepare(t, prev), nil))
	if same.ChangeVerdict != string(changetrack.VerdictSame) {
		t.Fatalf("verdict %q, want same", same.ChangeVerdict)
	}
	prev = same.ChangeRecord
	changed := f.save(t, "value-two", &prev, f.decide(t, f.prepare(t, prev), nil))
	if changed.ChangeVerdict != string(changetrack.VerdictChanged) {
		t.Fatalf("verdict %q, want changed", changed.ChangeVerdict)
	}
}

// Every decision Keeper cannot tie to this account, device, session, entry,
// record and challenge gives no verdict; the token is still sealed.
func TestGroupEncryptBoundTracked_RefusesDecisionsItCannotVerify(t *testing.T) {
	cases := map[string]func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision{
		"forged signature": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			d := f.decide(t, f.prepare(t, prev), nil)
			d.Signature = base64.StdEncoding.EncodeToString([]byte("forged"))
			return d
		},
		"expired": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			d := f.decide(t, f.prepare(t, prev), nil)
			f.clock.unix += 9
			return d
		},
		"other entry": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			return f.decide(t, f.prepare(t, prev), func(d *proto.ChangeCompareDecision) { d.EntryID = boundOther })
		},
		"other record digest": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			return f.decide(t, f.prepare(t, prev), func(d *proto.ChangeCompareDecision) {
				d.RecordDigest = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
			})
		},
		"other account": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			return f.decide(t, f.prepare(t, prev), func(d *proto.ChangeCompareDecision) { d.AccountID = boundOther })
		},
		"other device": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			return f.decide(t, f.prepare(t, prev), func(d *proto.ChangeCompareDecision) { d.DeviceID = boundOther })
		},
		"decision prepared for another record": func(t *testing.T, f *compareFixture, prev proto.ChangeRecord) *proto.ChangeCompareDecision {
			other := prev
			other.Seq = prev.Seq + 1
			return f.decide(t, f.prepare(t, other), nil)
		},
	}
	for name, build := range cases {
		f := newCompareFixture(t)
		prev := f.save(t, "value-one", nil, nil).ChangeRecord
		got := f.save(t, "value-one", &prev, build(t, f, prev))
		if got.ChangeVerdict != string(changetrack.VerdictUnknown) || got.CiphertextB64 == "" {
			t.Errorf("%s: verdict %q, want unknown with a token", name, got.ChangeVerdict)
		}
	}
}

// The review's probe: guessing a value against one record. One decision
// answers one comparison; every further guess gets no verdict.
func TestGroupEncryptBoundTracked_BruteForceStopsAfterTheFirstAttempt(t *testing.T) {
	f := newCompareFixture(t)
	prev := f.save(t, "4821", nil, nil).ChangeRecord
	d := f.decide(t, f.prepare(t, prev), nil)
	answered := 0
	for pin := 0; pin < 200; pin++ {
		got := f.save(t, fmt.Sprintf("%04d", pin), &prev, d)
		if got.ChangeVerdict == string(changetrack.VerdictSame) || got.ChangeVerdict == string(changetrack.VerdictChanged) {
			answered++
		}
	}
	if answered != 1 {
		t.Fatalf("%d guesses got a verdict, want only the first", answered)
	}
}

// A DEK rotation between two saves of one value: under a decision, the
// previous record is opened through the retained version's handle, unlabeled
// (legacy) or labeled for the same org, group and that version, and the new
// record is sealed under the current DEK. The verdict stays same.
func TestGroupEncryptBoundTracked_SameValueAcrossDEKVersionsUsesThePreviousHandle(t *testing.T) {
	for _, labeled := range []bool{false, true} {
		f := newCompareFixture(t)
		oldVersion := f.v.DekVersion - 1
		oldRaw := make([]byte, 32)
		if _, err := rand.Read(oldRaw); err != nil {
			t.Fatal(err)
		}
		label := sessions.Label{}
		if labeled {
			label = sessions.Label{OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: oldVersion}
		}
		oldHandle, _, err := f.deps.GroupSessions.OpenLabeled(append([]byte(nil), oldRaw...), label)
		if err != nil {
			t.Fatal(err)
		}
		scope := changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: f.v.OrgID, GroupID: f.v.GroupID, EntryID: trackEntry}
		old, err := changetrack.Seal(rand.Reader, oldRaw, scope, oldVersion, 4, []byte("value-one"))
		if err != nil {
			t.Fatal("seal failed")
		}
		prev := changeRecordData(old)
		resp := HandleGroupEncryptBoundTracked(f.deps, proto.GroupEncryptBoundTrackedRequest{
			GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
			TokenExpiry: f.expiry, EntryID: trackEntry, PreviousRecord: &prev, PreviousGroupHandle: oldHandle,
			CompareDecision: f.decide(t, f.prepare(t, prev), nil),
			PlaintextB64:    base64.StdEncoding.EncodeToString([]byte("value-one")),
		})
		data := trackedData(t, resp)
		if data.ChangeVerdict != string(changetrack.VerdictSame) || data.ChangeRecord.Seq != 5 || data.ChangeRecord.DekVersion != f.v.DekVersion {
			t.Fatalf("labeled=%v: verdict %q seq %d version %d, want same 5 current", labeled, data.ChangeVerdict, data.ChangeRecord.Seq, data.ChangeRecord.DekVersion)
		}
	}
}

// Even under a valid decision, a previous-version handle labeled for another
// group or version does not open the record: unknown.
func TestGroupEncryptBoundTracked_MismatchedPreviousHandleIsUnknownUnderADecision(t *testing.T) {
	for name, label := range map[string]func(f *compareFixture, v int) sessions.Label{
		"other group": func(f *compareFixture, v int) sessions.Label {
			return sessions.Label{OrgID: f.v.OrgID, GroupID: boundOther, DekVersion: v}
		},
		"other version": func(f *compareFixture, v int) sessions.Label {
			return sessions.Label{OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: v - 1}
		},
	} {
		f := newCompareFixture(t)
		oldVersion := f.v.DekVersion - 1
		oldRaw := make([]byte, 32)
		if _, err := rand.Read(oldRaw); err != nil {
			t.Fatal(err)
		}
		oldHandle, _, err := f.deps.GroupSessions.OpenLabeled(append([]byte(nil), oldRaw...), label(f, oldVersion))
		if err != nil {
			t.Fatal(err)
		}
		scope := changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: f.v.OrgID, GroupID: f.v.GroupID, EntryID: trackEntry}
		old, err := changetrack.Seal(rand.Reader, oldRaw, scope, oldVersion, 4, []byte("value-one"))
		if err != nil {
			t.Fatal("seal failed")
		}
		prev := changeRecordData(old)
		data := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, proto.GroupEncryptBoundTrackedRequest{
			GroupHandle: f.handle, OrgID: f.v.OrgID, GroupID: f.v.GroupID, DekVersion: f.v.DekVersion,
			TokenExpiry: f.expiry, EntryID: trackEntry, PreviousRecord: &prev, PreviousGroupHandle: oldHandle,
			CompareDecision: f.decide(t, f.prepare(t, prev), nil),
			PlaintextB64:    base64.StdEncoding.EncodeToString([]byte("value-one")),
		}))
		if data.ChangeVerdict != string(changetrack.VerdictUnknown) {
			t.Errorf("%s: verdict %q, want unknown", name, data.ChangeVerdict)
		}
	}
}

// Personal entries have no comparison decision (lv83 H1): a previous record
// is never compared, the verdict is unknown, and the token and the next
// record are still sealed under the account scope.
func TestDEKUnwrapAndEncryptBoundTracked_PersonalComparisonIsOff(t *testing.T) {
	deps, _, _, wrapped, _ := newBoundPersonalFixture(t)
	first := personalTrackedData(t, HandleDEKUnwrapAndEncryptBoundTracked(deps, personalTrackedReq(wrapped, "value-one", nil)))
	prev := first.ChangeRecord
	for _, value := range []string{"value-one", "value-two"} {
		got := personalTrackedData(t, HandleDEKUnwrapAndEncryptBoundTracked(deps, personalTrackedReq(wrapped, value, &prev)))
		if got.ChangeVerdict != string(changetrack.VerdictUnknown) || got.CiphertextB64 == "" || got.ChangeRecord.Seq != 2 {
			t.Fatalf("personal: verdict %q seq %d, want unknown 2 with a token", got.ChangeVerdict, got.ChangeRecord.Seq)
		}
	}
}
