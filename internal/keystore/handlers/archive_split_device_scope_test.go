package handlers

import (
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// newDeviceScopeSplitFixture leaves the org on the device-wide archive slot
// (the org never rotated to its own key), which other orgs on the device may
// share.
func newDeviceScopeSplitFixture(t *testing.T) *splitFixture {
	t.Helper()
	f := &splitFixture{auditFixture: newAuditFixture(t)}
	f.deps.ArchiveSplitChallenges = NewArchiveShareChallengeStore()
	f.deps.ArchiveProofChallenges = NewArchiveShareChallengeStore()
	if err := f.store.Set(config.Service, config.DeviceID, splitTestDevice); err != nil {
		t.Fatal(err)
	}
	seedActiveArchiveKey(t, f.deps)
	slot, pub, found, err := keychain.FindArchiveKey(f.store, keychain.OrgArchiveActiveCandidates(f.v.OrgID))
	if err != nil || !found || slot.Scope != keychain.ArchiveScopeDevice {
		t.Fatal("fixture did not resolve to the device-wide slot")
	}
	f.archive = pub
	var pems []string
	f.admins, pems = genAdminKeys(t, len(splitTestRecipientAccounts))
	f.request = proto.ArchiveKeySplitRequest{
		OperationID: splitTestOperation, AccountID: f.v.AccountID, OrgID: f.v.OrgID, ThresholdN: 2,
		RecipientPublicKeys: pems, RecipientAccountIDs: append([]string(nil), splitTestRecipientAccounts...),
		ConfigDigest: splitTestConfig,
	}
	private := map[string]bool{}
	for _, s := range keychain.OrgArchiveActiveCandidates(f.v.OrgID) {
		private[s.PrivateAccount] = true
	}
	f.probe = &splitAccessProbe{SecretStore: f.store, private: private}
	f.deps.Store = f.probe
	return f
}

func TestArchiveKeySplitRefusesDeviceWideSlot(t *testing.T) {
	f := newDeviceScopeSplitFixture(t)
	req := f.authorize(t, f.request)
	f.resetProbe()
	assertSplitRefusedUntouched(t, f, HandleArchiveKeySplit(f.deps, req))
}

// A device-scope journal can exist only from preparation outside the gate.
// Finalization and abandonment still refuse to delete anything for it.
func deviceScopeJournal(t *testing.T) (*finalizeFixture, proto.ArchiveKeySplitResponseData) {
	t.Helper()
	sf := newDeviceScopeSplitFixture(t)
	spki, err := crypto.RewrapKeyFingerprint(sf.archive)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := proto.ArchiveSplitRequestDigest(sf.request)
	if err != nil {
		t.Fatal(err)
	}
	response := prepareArchiveKeySplit(sf.deps, sf.request, archiveSplitBinding{
		OrgID: sf.v.OrgID, AccountID: sf.v.AccountID, ConfigDigest: splitTestConfig,
		ArchiveKeySPKIFingerprint: spki, SplitRequestDigest: digest,
	})
	if !response.Success {
		t.Fatalf("device-scope preparation: %s", response.Error)
	}
	slot, _, _, _ := keychain.FindArchiveKey(sf.store, keychain.OrgArchiveActiveCandidates(sf.v.OrgID))
	data := response.Data.(proto.ArchiveKeySplitResponseData)
	f := &finalizeFixture{splitFixture: sf, split: data, slot: slot, spki: spki}
	f.resetProbe()
	return f, data
}

func TestArchiveSplitFinalizeRefusesDeviceWideSlot(t *testing.T) {
	f, _ := deviceScopeJournal(t)
	r := HandleArchiveSplitFinalize(f.deps, f.receipt(t, nil))
	if r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("device-scope finalization answer = %+v", r)
	}
	if f.probe.deletes != 0 || f.probe.sets != 0 || !f.privatePresent(t) || !f.journalPresent(t) {
		t.Fatal("device-scope finalization deleted or changed something")
	}
}

func TestArchiveSplitAbandonRefusesDeviceWideSlot(t *testing.T) {
	f, _ := deviceScopeJournal(t)
	if r := HandleArchiveSplitAbandon(f.deps, f.closure(t, nil)); r.Success {
		t.Fatal("device-scope abandon was accepted")
	}
	if f.probe.deletes != 0 || !f.journalPresent(t) || !f.privatePresent(t) {
		t.Fatal("device-scope abandon deleted something")
	}
}
