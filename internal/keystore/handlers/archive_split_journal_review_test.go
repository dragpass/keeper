package handlers

import (
	"errors"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// interruptSplit leaves a "writing" record: the manifest and parts 0 and 1.
func (c *splitCase) interruptSplit(t *testing.T) {
	t.Helper()
	inner := c.f.deps.Store
	fault := &journalFaultStore{SecretStore: inner, failSet: 4, afterFailSetsAllFail: true}
	c.f.deps.Store = fault
	if r := c.split(t); r.Success {
		t.Fatal("interrupted split succeeded")
	}
	c.f.deps.Store = inner
	if j, found, err := loadArchiveSplitJournal(c.f.store, c.slot); err != nil || !found || j.State != archiveSplitJournalWriting {
		t.Fatalf("no writing record: %+v %v %v", j, found, err)
	}
}

// A confirmed unregistered closure does not take an interrupted split write
// as evidence of registration: it removes the record with the staged target.
func TestArchiveSplitUnregisteredClosureRemovesWritingRecord(t *testing.T) {
	c := newSplitCase(t, "reconfiguration", 3)
	c.interruptSplit(t)
	f := c.f
	org, op := f.request.OrgID, f.request.OperationID
	status := HandleArchiveSplitStatus(f.deps, proto.ArchiveSplitStatusRequest{OrgID: org, Kind: "reconfiguration"})
	if !status.Success {
		t.Fatal(status.ErrorCode)
	}
	st := status.Data.(proto.ArchiveSplitStateResponseData)
	proof := proto.ArchiveUnregisteredClosure{OperationID: op, OrgID: org, RequesterAccountID: f.request.AccountID, RequesterDeviceID: splitTestDevice, SourceConfigDigest: strings.Repeat("b", 64), Status: "cancelled", ServerKeyVersion: 1}
	proof.Signature = f.sign(t, proof.Canonical())
	r := HandleArchiveSplitAbandon(f.deps, proto.ArchiveSplitAbandonRequest{OrgID: org, UnregisteredClosure: &proof, ExpectedFingerprint: st.Fingerprint, Confirmed: true, ExpectedLoginGeneration: st.LoginGeneration})
	if !r.Success {
		t.Fatalf("unregistered closure with a writing record: %s %s", r.ErrorCode, r.Error)
	}
	if left := journalItems(t, f); len(left) != 0 {
		t.Fatalf("items left: %v", left)
	}
	if _, err := c.slot.GetPublic(f.store); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("staged key kept")
	}
}

// Finalization refuses an interrupted split write with not_found and
// deletes nothing, even for a receipt naming its shares digest.
func TestArchiveSplitFinalizeRefusesWritingRecord(t *testing.T) {
	c := newSplitCase(t, "activation", 3)
	c.interruptSplit(t)
	j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
	if err != nil {
		t.Fatal(err)
	}
	ff := &finalizeFixture{splitFixture: c.f, spki: splitCaseSPKI(t, c.f)}
	c.f.resetProbe()
	r := HandleArchiveSplitFinalize(c.f.deps, ff.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.SharesDigest = j.SharesDigest }))
	if r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("finalization of a writing record answered %+v", r)
	}
	if c.f.probe.sets != 0 || c.f.probe.deletes != 0 {
		t.Fatal("refused finalization wrote or deleted")
	}
	if _, err := c.slot.GetPrivate(c.f.store); err != nil {
		t.Fatal("archive private key lost")
	}
}

// A reconfiguration closure resumed after its facts were recorded removes the
// split record even when the manifest no longer parses, as documented.
func TestArchiveSplitResumedReconfigurationCleanupRemovesUnparsableManifest(t *testing.T) {
	c := newSplitCase(t, "reconfiguration", 3)
	if r := c.split(t); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	inner := c.f.deps.Store
	c.f.deps.Store = &journalFaultStore{SecretStore: inner, failDel: 1}
	if r := c.abandon(t); r.ErrorCode != string(errs.ErrCodeArchiveSplitCleanupPending) {
		t.Fatalf("interrupted closure answered %+v", r)
	}
	c.f.deps.Store = inner
	if err := c.f.store.Set(config.Service, archiveSplitJournalAccount(c.slot), "not a manifest"); err != nil {
		t.Fatal(err)
	}
	if r := c.abandon(t); !r.Success {
		t.Fatalf("resumed closure: %s %s", r.ErrorCode, r.Error)
	}
	if left := journalItems(t, c.f); len(left) != 0 {
		t.Fatalf("items left: %v", left)
	}
}

// A manifest of an unknown version is never read as a record: a split retry
// answers not_found and writes nothing.
func TestArchiveSplitRefusesUnknownManifestVersion(t *testing.T) {
	c := newSplitCase(t, "activation", 3)
	if r := c.split(t); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
	if err != nil {
		t.Fatal(err)
	}
	j.Version = archiveSplitManifestVersion + 1
	if err := writeArchiveSplitJournal(c.f.store, c.slot, j); err != nil {
		t.Fatal(err)
	}
	c.f.resetProbe()
	if r := c.split(t); r.Success || r.ErrorCode != string(errs.ErrCodeNotFound) {
		t.Fatalf("unknown version answered %+v", r)
	}
	if c.f.probe.sets != 0 || c.f.probe.deletes != 0 {
		t.Fatal("refusal wrote or deleted")
	}
}

// Deleting a record also removes parts past its recorded count.
func TestArchiveSplitDeleteRemovesPartsPastTheCount(t *testing.T) {
	c := newSplitCase(t, "activation", 3)
	if r := c.split(t); !r.Success {
		t.Fatal(r.ErrorCode)
	}
	j, _, err := loadArchiveSplitJournal(c.f.store, c.slot)
	if err != nil {
		t.Fatal(err)
	}
	for i := j.PartCount; i < j.PartCount+2; i++ {
		c.setPart(t, i, encodeArchiveSplitPart(j.OperationID, j.ResultDigest, i, j.PartCount, []byte("{}")))
	}
	if r := c.abandon(t); !r.Success {
		t.Fatalf("closure: %s %s", r.ErrorCode, r.Error)
	}
	if left := journalItems(t, c.f); len(left) != 0 {
		t.Fatalf("items left: %v", left)
	}
}

// failCleanupPendingWrite refuses the write that records cleanup_pending, as
// a Keeper that stops right after a failed key delete never writes it.
type failCleanupPendingWrite struct{ keychain.SecretStore }

func (s failCleanupPendingWrite) Set(service, account, value string) error {
	if strings.HasPrefix(account, splitJournalPrefix) && strings.Contains(value, archiveSplitJournalCleanupPending) {
		return errInjectedStorage
	}
	return s.SecretStore.Set(service, account, value)
}

// Finalization records "deleting" before it deletes the key, so a closure
// receipt can never abandon the record once deletion may have started, even
// when the cleanup_pending state was never written.
func TestArchiveSplitDeletingMarkBlocksClosure(t *testing.T) {
	c := newSplitCase(t, "activation", 3)
	split := c.split(t)
	if !split.Success {
		t.Fatal(split.ErrorCode)
	}
	c.f.probe.deleteHook = func(account string) error {
		if account == c.slot.PrivateAccount {
			return errInjectedStorage
		}
		return nil
	}
	inner := c.f.deps.Store
	c.f.deps.Store = failCleanupPendingWrite{inner}
	if r := c.finalize(t, split.Data.(proto.ArchiveKeySplitResponseData).Shares); r.Success {
		t.Fatal("finalization succeeded without deleting the key")
	}
	c.f.deps.Store = inner
	c.f.probe.deleteHook = nil
	if r := c.abandon(t); r.Success {
		t.Fatal("closure abandoned a record whose deletion started")
	}
	if left := journalItems(t, c.f); len(left) == 0 {
		t.Fatal("record lost")
	}
}
