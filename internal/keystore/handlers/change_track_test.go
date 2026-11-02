// Tests for the tracked bound-encrypt actions and the change-baseline action
// (docs/protocol.md "Entry value-change tracking"). Test values are compared
// in memory and never printed.

package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/changetrack"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

const trackEntry = "4e5f6a7b-8c9d-4eaf-b0c1-d2e3f4a5b6c7"

func trackGroupScope() changetrack.Scope {
	return changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: boundOrg, GroupID: boundGroup, EntryID: trackEntry}
}

func (f *boundGroupFixture) trackedReq(value string, prev *proto.ChangeRecord) proto.GroupEncryptBoundTrackedRequest {
	return proto.GroupEncryptBoundTrackedRequest{
		GroupHandle: f.handle, OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7,
		TokenExpiry: boundLater, EntryID: trackEntry,
		PlaintextB64:   base64.StdEncoding.EncodeToString([]byte(value)),
		PreviousRecord: prev,
	}
}

func trackedData(t *testing.T, resp proto.BaseResponse) proto.GroupEncryptBoundTrackedResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("tracked encrypt failed: %s", resp.ErrorCode)
	}
	return resp.Data.(proto.GroupEncryptBoundTrackedResponseData)
}

func sealedOf(t *testing.T, r proto.ChangeRecord) changetrack.Sealed {
	t.Helper()
	iv, err1 := base64.StdEncoding.DecodeString(r.IVB64)
	ct, err2 := base64.StdEncoding.DecodeString(r.CiphertextB64)
	if err1 != nil || err2 != nil {
		t.Fatal("record is not base64")
	}
	return changetrack.Sealed{IV: iv, Ciphertext: ct, DekVersion: r.DekVersion, Seq: r.Seq}
}

func TestGroupEncryptBoundTracked_FirstSaveIsBaselineAndSealsTheToken(t *testing.T) {
	f := newBoundGroupFixture(t)
	data := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq("value-one", nil)))
	if data.ChangeVerdict != string(changetrack.VerdictBaseline) || data.ChangeRecord.Seq != 1 || data.ChangeRecord.DekVersion != 7 {
		t.Fatalf("verdict %q seq %d version %d, want baseline 1 7", data.ChangeVerdict, data.ChangeRecord.Seq, data.ChangeRecord.DekVersion)
	}
	if changetrack.Compare(f.raw, trackGroupScope(), sealedOf(t, data.ChangeRecord), []byte("value-one")) != changetrack.VerdictSame {
		t.Fatal("record does not describe the sealed value")
	}
	// The token opens like any bound token.
	resp := HandleGroupDecryptBoundToClipboard(f.deps, f.decryptReq(data.IVB64, data.CiphertextB64, "", boundLater))
	want := sha256.Sum256([]byte("value-one"))
	if got, ok := f.mc.LastHash(); !resp.Success || !ok || got != want {
		t.Fatal("tracked token does not open as a bound token with the saved value")
	}
}

func openLabeledForTest(t *testing.T, f *boundGroupFixture, raw []byte, label sessions.Label) string {
	t.Helper()
	handle, _, err := f.deps.GroupSessions.OpenLabeled(append([]byte(nil), raw...), label)
	if err != nil {
		t.Fatal("open labeled failed")
	}
	t.Cleanup(func() { f.deps.GroupSessions.Close(handle) })
	return handle
}

// Comparison failures never block the encryption: each case still returns a
// bound token and a fresh record at the next sequence, with verdict unknown.
func TestGroupEncryptBoundTracked_UnverifiablePreviousRecordIsUnknownAndStillSeals(t *testing.T) {
	f := newBoundGroupFixture(t)
	oldRaw := make([]byte, 32)
	if _, err := rand.Read(oldRaw); err != nil {
		t.Fatal(err)
	}
	old, err := changetrack.Seal(rand.Reader, oldRaw, trackGroupScope(), 6, 4, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	same, err := changetrack.Seal(rand.Reader, f.raw, trackGroupScope(), 7, 4, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	damaged := changeRecordData(same)
	damaged.CiphertextB64 = "not base64"
	wrongGroup := openLabeledForTest(t, f, oldRaw, sessions.Label{OrgID: boundOrg, GroupID: boundOther, DekVersion: 6})
	wrongVersion := openLabeledForTest(t, f, oldRaw, sessions.Label{OrgID: boundOrg, GroupID: boundGroup, DekVersion: 5})
	otherEntry, err := changetrack.Seal(rand.Reader, f.raw, changetrack.Scope{Kind: changetrack.ScopeGroup, ScopeID: boundOrg, GroupID: boundGroup, EntryID: boundTable}, 7, 4, []byte("value-one"))
	if err != nil {
		t.Fatal("seal failed")
	}
	oldRecord, otherEntryRecord := changeRecordData(old), changeRecordData(otherEntry)
	closed, _, err := f.deps.GroupSessions.Open(append([]byte(nil), oldRaw...))
	if err != nil {
		t.Fatal("open failed")
	}
	f.deps.GroupSessions.Close(closed)

	cases := []struct {
		name   string
		prev   proto.ChangeRecord
		handle string
	}{
		{"other version without its handle", oldRecord, ""},
		{"previous handle of another group", oldRecord, wrongGroup},
		{"previous handle of another version", oldRecord, wrongVersion},
		{"closed previous handle", oldRecord, closed},
		{"damaged bytes", damaged, ""},
		{"record of another entry", otherEntryRecord, ""},
	}
	for _, tc := range cases {
		prev := tc.prev
		req := f.trackedReq("value-one", &prev)
		req.PreviousGroupHandle = tc.handle
		resp := HandleGroupEncryptBoundTracked(f.deps, req)
		if !resp.Success {
			t.Errorf("%s: encryption was blocked (%s)", tc.name, resp.ErrorCode)
			continue
		}
		data := resp.Data.(proto.GroupEncryptBoundTrackedResponseData)
		if data.ChangeVerdict != string(changetrack.VerdictUnknown) || data.ChangeRecord.Seq != 5 || data.CiphertextB64 == "" {
			t.Errorf("%s: verdict %q seq %d, want unknown 5 with a token", tc.name, data.ChangeVerdict, data.ChangeRecord.Seq)
		}
	}
}

func TestGroupEncryptBoundTracked_RefusesDecryptOnlyAndExpired(t *testing.T) {
	f := newBoundGroupFixture(t)
	dOnly := openLabeledForTest(t, f, f.raw, sessions.Label{OrgID: boundOrg, GroupID: boundGroup, DekVersion: 7, GrantPolicy: proto.GrantPolicyDecryptOnlyV1})
	req := f.trackedReq("value-one", nil)
	req.GroupHandle = dOnly
	wantCode(t, HandleGroupEncryptBoundTracked(f.deps, req), proto.GroupPolicyDecryptOnly)
	req = f.trackedReq("value-one", nil)
	req.TokenExpiry = "1700000000"
	wantCode(t, HandleGroupEncryptBoundTracked(f.deps, req), proto.TokenExpired)
}

func TestGroupEncryptBoundTracked_LogsNoValueKeyOrRecord(t *testing.T) {
	f := newBoundGroupFixture(t)
	log := testdouble.NewMemoryLogger()
	f.deps.Logger = log
	const sentinel = "TRACKED_ENCRYPT_LOGGER_LEAK_SENTINEL"
	first := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq(sentinel, nil)))
	prev := first.ChangeRecord
	second := trackedData(t, HandleGroupEncryptBoundTracked(f.deps, f.trackedReq(sentinel, &prev)))
	for _, secret := range []string{sentinel, base64.StdEncoding.EncodeToString([]byte(sentinel)),
		base64.StdEncoding.EncodeToString(f.raw), first.ChangeRecord.CiphertextB64, second.ChangeRecord.CiphertextB64, trackEntry} {
		if log.Contains(secret) {
			t.Fatal("logger recorded a value, key, record or identifier")
		}
	}
}

// ─── Personal ────────────────────────────────────────────────────────────

func personalTrackedReq(wrapped, value string, prev *proto.ChangeRecord) proto.DEKUnwrapAndEncryptBoundTrackedRequest {
	return proto.DEKUnwrapAndEncryptBoundTrackedRequest{
		EncryptedDEKB64: wrapped, TokenExpiry: boundLater, EntryID: trackEntry,
		PlaintextB64:   base64.StdEncoding.EncodeToString([]byte(value)),
		PreviousRecord: prev,
	}
}

func personalTrackedData(t *testing.T, resp proto.BaseResponse) proto.DEKUnwrapAndEncryptBoundTrackedResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("personal tracked encrypt failed: %s", resp.ErrorCode)
	}
	return resp.Data.(proto.DEKUnwrapAndEncryptBoundTrackedResponseData)
}

// The personal scope is the signed-in account binding, never a caller value.
func TestDEKUnwrapAndEncryptBoundTracked_BaselineUnderTheAccountScope(t *testing.T) {
	deps, _, _, wrapped, dek := newBoundPersonalFixture(t)
	first := personalTrackedData(t, HandleDEKUnwrapAndEncryptBoundTracked(deps, personalTrackedReq(wrapped, "value-one", nil)))
	if first.ChangeVerdict != string(changetrack.VerdictBaseline) || first.ChangeRecord.Seq != 1 || first.ChangeRecord.DekVersion != 1 {
		t.Fatalf("verdict %q seq %d version %d, want baseline 1 1", first.ChangeVerdict, first.ChangeRecord.Seq, first.ChangeRecord.DekVersion)
	}
	scope := changetrack.Scope{Kind: changetrack.ScopePersonal, ScopeID: boundAccount, EntryID: trackEntry}
	if changetrack.Compare(dek, scope, sealedOf(t, first.ChangeRecord), []byte("value-one")) != changetrack.VerdictSame {
		t.Fatal("personal record is not bound to the signed-in account")
	}
}
