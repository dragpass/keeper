// archive_session_org_slot_test.go — the recovery-session key slot is per
// organization (lv90 K0).
//
// The server allows one open session per organization, so an owner of two
// organizations on one device can hold two open sessions at once. Each
// session's private key lives in its organization's slot; a combine for one
// organization reads only that slot.

package handlers

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const sessionTestGroup = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func sessionGrantContext(orgID string) *proto.GrantContext {
	return &proto.GrantContext{Policy: proto.GrantPolicyLegacy, OrgID: orgID, GroupID: sessionTestGroup, DekVersion: 1}
}

func beginSessionFor(t *testing.T, deps Deps, orgID string) string {
	t.Helper()
	resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: orgID})
	if !resp.Success {
		t.Fatalf("session begin for %s: %+v", orgID, resp)
	}
	return resp.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey
}

// sessionCombineRequest builds a combine whose shares of a fresh archive key
// are wrapped to sessionPub, and whose old grant opens to dek under orgID.
func sessionCombineRequest(t *testing.T, orgID, sessionPub string, dek []byte) (proto.ArchiveQuorumCombineAndRewrapRequest, *crypto.KeyPair) {
	t.Helper()
	archive, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := crypto.SplitSecret([]byte(archive.PrivateKey), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.ParsePublicKey(sessionPub)
	if err != nil {
		t.Fatal(err)
	}
	gc := sessionGrantContext(orgID)
	archivePub, err := crypto.ParsePublicKey(archive.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wrappedOld, err := wrapGrant(archivePub, dek, gc)
	if err != nil {
		t.Fatal(err)
	}
	member, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.ArchiveQuorumCombineAndRewrapRequest{
		WrappedOldDEKB64: base64.StdEncoding.EncodeToString(wrappedOld),
		Recipients:       exemptRecipients(member.PublicKey),
		GrantContext:     gc,
	}
	for _, share := range shares {
		wk, ct, err := crypto.HybridWrap(pub, crypto.SerializeShare(share))
		if err != nil {
			t.Fatal(err)
		}
		req.RewrappedShares = append(req.RewrappedShares, proto.RewrappedShareInput{WrappedKey: wk, Ciphertext: ct})
	}
	return req, member
}

func sessionTestDEK() []byte {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(0xA0 + i)
	}
	return dek
}

// Two organizations' sessions opened on one device keep their own keys: the
// second begin does not replace the first organization's session key.
func TestArchiveSession_TwoOrgsKeepTheirOwnSessionKeys(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	pubA := beginSessionFor(t, deps, testOrgA)
	pubB := beginSessionFor(t, deps, testOrgB)
	if pubA == pubB {
		t.Fatal("two organizations got the same session key")
	}
	for orgID, pub := range map[string]string{testOrgA: pubA, testOrgB: pubB} {
		req, member := sessionCombineRequest(t, orgID, pub, sessionTestDEK())
		resp := archiveQuorumCombineAndRewrap(deps, orgID, req)
		if !resp.Success {
			t.Fatalf("combine for %s with its own session: %+v", orgID, resp)
		}
		assertMemberGrantOpens(t, resp, member, sessionGrantContext(orgID), sessionTestDEK())
	}
}

func assertMemberGrantOpens(t *testing.T, resp proto.BaseResponse, member *crypto.KeyPair, gc *proto.GrantContext, want []byte) {
	t.Helper()
	out := resp.Data.(proto.ArchiveQuorumCombineAndRewrapResponseData)
	enc, err := base64.StdEncoding.DecodeString(out.Grants[0].EncryptedGroupDEKB64)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.ParsePrivateKey(member.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unwrapGrant(priv, enc, gc)
	if err != nil || string(got) != string(want) {
		t.Fatal("the re-grant does not open to the original DEK")
	}
}

// sessionReadProbe counts reads of one keychain account.
type sessionReadProbe struct {
	keychain.SecretStore
	account string
	reads   int
}

func (p *sessionReadProbe) Get(service, account string) (string, error) {
	if account == p.account {
		p.reads++
	}
	return p.SecretStore.Get(service, account)
}

// saveLegacyDeviceSession writes a session key pair into the device-wide slot
// a Keeper before lv90 used, and returns its public key.
func saveLegacyDeviceSession(t *testing.T, store keychain.SecretStore) string {
	t.Helper()
	legacy, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.LegacyOrgArchiveSessionPrivateKey, legacy.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(config.Service, config.LegacyOrgArchiveSessionPublicKey, legacy.PublicKey); err != nil {
		t.Fatal(err)
	}
	return legacy.PublicKey
}

// A session opened under the device-wide slot names no organization, so a
// combine for any organization fails closed instead of reading it.
func TestArchiveSession_CombineNeverReadsTheDeviceWideSlot(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	legacyPub := saveLegacyDeviceSession(t, store)
	probe := &sessionReadProbe{SecretStore: store, account: config.LegacyOrgArchiveSessionPrivateKey}
	deps.Store = probe
	req, _ := sessionCombineRequest(t, testOrgA, legacyPub, sessionTestDEK())
	resp := archiveQuorumCombineAndRewrap(deps, testOrgA, req)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeNotFound) || resp.Data != nil {
		t.Fatalf("combine over a device-wide session: %+v", resp)
	}
	if probe.reads != 0 {
		t.Fatal("combine read the device-wide session key")
	}
}

// Session begin and end name their organization; without one nothing is
// written or removed.
func TestArchiveSession_BeginAndEndRequireOrgID(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	beginSessionFor(t, deps, testOrgA)
	for name, orgID := range map[string]string{"missing": "", "malformed": "not-a-uuid"} {
		before := store.Snapshot()
		begin := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: orgID})
		end := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: orgID, Fingerprint: strings.Repeat("0", 64)})
		if begin.Success || begin.ErrorCode != string(errs.ErrCodeValidation) || end.Success || end.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s org_id: begin %+v end %+v", name, begin, end)
		}
		if !reflect.DeepEqual(before, store.Snapshot()) {
			t.Fatalf("%s org_id changed the keychain", name)
		}
	}
}

// Ending one organization's session leaves another organization's open
// session usable.
func TestArchiveSession_EndRemovesOnlyItsOwnOrgSession(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	pubA := beginSessionFor(t, deps, testOrgA)
	pubB := beginSessionFor(t, deps, testOrgB)
	end := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: fingerprintBase64Public(pubA)})
	if !end.Success || !end.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatalf("end for A: %+v", end)
	}
	if priv, _ := keychain.GetArchiveSessionPrivateKey(store, testOrgA); priv != "" {
		t.Fatal("A's session key survived its end")
	}
	req, member := sessionCombineRequest(t, testOrgB, pubB, sessionTestDEK())
	resp := archiveQuorumCombineAndRewrap(deps, testOrgB, req)
	if !resp.Success {
		t.Fatalf("B's session after A ended: %+v", resp)
	}
	assertMemberGrantOpens(t, resp, member, sessionGrantContext(testOrgB), sessionTestDEK())
}

// The device-wide slot of a Keeper before lv90 may hold the session key of an
// in-flight recovery of some organization on this device; its organization is
// not recorded. While it exists, begin for any organization stops with
// archive_session_legacy_slot_present and changes nothing: no deletion, no
// move into an organization slot, no fallback.
func TestArchiveSession_BeginRefusesWhileTheDeviceWideSlotExists(t *testing.T) {
	for _, half := range []string{"both", "private", "public"} {
		t.Run(half, func(t *testing.T) {
			deps, _, store := newTestDeps(t)
			setSlotTestOwner(t, deps, slotTestAccount)
			saveLegacyDeviceSession(t, store)
			if half == "private" {
				_ = store.Delete(config.Service, config.LegacyOrgArchiveSessionPublicKey)
			} else if half == "public" {
				_ = store.Delete(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
			}
			before := store.Snapshot()
			resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA})
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) || resp.Data != nil {
				t.Fatalf("begin with a device-wide session slot (%s): %+v", half, resp)
			}
			if !reflect.DeepEqual(before, store.Snapshot()) {
				t.Fatal("a refused begin changed the keychain")
			}
		})
	}
}

// archive_session_end ends only its organization's session. The device-wide
// slot is left exactly as it was.
func TestArchiveSession_EndLeavesTheDeviceWideSlot(t *testing.T) {
	deps, _, store := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	saveLegacyDeviceSession(t, store)
	priv, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
	pub, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPublicKey)
	resp := HandleArchiveSessionEnd(deps, proto.ArchiveSessionEndRequest{OrgID: testOrgA, Fingerprint: fingerprintBase64Public(pub)})
	if !resp.Success || resp.Data.(proto.ArchiveSessionEndResponseData).Ended {
		t.Fatalf("end: %+v", resp)
	}
	gotPriv, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPrivateKey)
	gotPub, _ := store.Get(config.Service, config.LegacyOrgArchiveSessionPublicKey)
	if gotPriv != priv || gotPub != pub {
		t.Fatal("end changed the device-wide session slot")
	}
}

// Device-wide slots have no owner field. Confirmation cannot establish who opened one.
func TestArchiveSession_LegacyDiscardPreservesUnknownOwner(t *testing.T) {
	deps, _, store := newTestDeps(t)
	account, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, account.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keychain.SetAccountBinding(store, "11111111-1111-4111-8111-111111111111", "owner", true); err != nil {
		t.Fatal(err)
	}
	beginSessionFor(t, deps, testOrgB)
	saveLegacyDeviceSession(t, store)
	before := store.Snapshot()
	refused := HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{})
	if refused.Success || refused.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("discard without confirmation: %+v", refused)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("an unconfirmed discard changed the keychain")
	}
	resp := HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) || resp.Data != nil {
		t.Fatalf("expected refusal for ownerless slot, got success=%v code=%q", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("a confirmed discard changed the keychain")
	}
	if resp := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA}); resp.ErrorCode != string(errs.ErrCodeArchiveSessionLegacySlotPresent) {
		t.Fatal("begin did not remain blocked")
	}
}

func TestArchiveSession_LegacyDiscardEmpty(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	setSlotTestOwner(t, deps, slotTestAccount)
	resp := HandleArchiveSessionLegacyDiscard(deps, proto.ArchiveSessionLegacyDiscardRequest{ConfirmDiscard: true})
	if !resp.Success || resp.Data.(proto.ArchiveSessionLegacyDiscardResponseData).Discarded {
		t.Fatal("expected an empty slot")
	}
}
