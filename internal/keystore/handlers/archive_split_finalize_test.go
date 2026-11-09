package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type finalizeFixture struct {
	*splitFixture
	split proto.ArchiveKeySplitResponseData
	slot  keychain.ArchiveKeySlot
	spki  string
}

// newFinalizeFixture leaves an authorized, journaled split of the org
// archive key whose private key is still retained.
func newFinalizeFixture(t *testing.T) *finalizeFixture {
	t.Helper()
	sf := newSplitFixture(t)
	response := HandleArchiveKeySplit(sf.deps, sf.authorize(t, sf.request))
	if !response.Success {
		t.Fatalf("authorized split refused: %s", response.Error)
	}
	slot, _, found, err := keychain.FindArchiveKey(sf.store, keychain.OrgArchiveActiveCandidates(sf.v.OrgID))
	if err != nil || !found {
		t.Fatal("archive key slot missing")
	}
	spki, err := crypto.RewrapKeyFingerprint(sf.archive)
	if err != nil {
		t.Fatal(err)
	}
	f := &finalizeFixture{splitFixture: sf, split: response.Data.(proto.ArchiveKeySplitResponseData), slot: slot, spki: spki}
	f.resetProbe()
	return f
}

func (f *finalizeFixture) receipt(t *testing.T, mutate func(*proto.ArchiveSplitFinalizationReceipt)) proto.ArchiveSplitFinalizeRequest {
	t.Helper()
	r := proto.ArchiveSplitFinalizationReceipt{
		OperationID: splitTestOperation, OrgID: f.v.OrgID, ArchiveKeySPKIFingerprint: f.spki,
		ConfigDigest: splitTestConfig, SharesDigest: proto.ArchiveSplitSharesDigest(f.split.Shares),
		FinalizedAt: f.clock.now().Unix(), ServerKeyVersion: 1,
	}
	if mutate != nil {
		mutate(&r)
	}
	r.Signature = f.sign(t, proto.ArchiveSplitFinalizationReceiptCanonical(r))
	return proto.ArchiveSplitFinalizeRequest{OrgID: f.v.OrgID, Receipt: &r}
}

func (f *finalizeFixture) closure(t *testing.T, mutate func(*proto.ArchiveSplitClosureReceipt)) proto.ArchiveSplitAbandonRequest {
	t.Helper()
	r := proto.ArchiveSplitClosureReceipt{
		OperationID: splitTestOperation, OrgID: f.v.OrgID, Status: proto.ArchiveSplitClosedCancelled,
		ArchiveKeySPKIFingerprint: f.spki, ServerKeyVersion: 1,
	}
	if mutate != nil {
		mutate(&r)
	}
	r.Signature = f.sign(t, proto.ArchiveSplitClosureReceiptCanonical(r))
	return proto.ArchiveSplitAbandonRequest{OrgID: f.v.OrgID, Receipt: &r}
}

func (f *finalizeFixture) privatePresent(t *testing.T) bool {
	t.Helper()
	_, err := f.store.Get(config.Service, f.slot.PrivateAccount)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (f *finalizeFixture) journalPresent(t *testing.T) bool {
	t.Helper()
	_, err := f.store.Get(config.Service, "archive_quorum_split_pending:"+f.slot.PrivateAccount)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (f *finalizeFixture) status(t *testing.T) proto.ArchiveSplitStateResponseData {
	t.Helper()
	r := HandleArchiveSplitStatus(f.deps, proto.ArchiveSplitStatusRequest{OrgID: f.v.OrgID})
	if !r.Success {
		t.Fatalf("status refused: %s %s", r.ErrorCode, r.Error)
	}
	return r.Data.(proto.ArchiveSplitStateResponseData)
}

func TestArchiveSplitFinalizeDeletesOriginalKeyAndJournal(t *testing.T) {
	f := newFinalizeFixture(t)
	r := HandleArchiveSplitFinalize(f.deps, f.receipt(t, nil))
	if !r.Success {
		t.Fatalf("valid finalization refused: %s %s", r.ErrorCode, r.Error)
	}
	if got := r.Data.(proto.ArchiveSplitStateResponseData); got.State != proto.ArchiveSplitStateFinalized || got.OperationID != splitTestOperation {
		t.Fatalf("finalize answer = %+v", got)
	}
	if f.privatePresent(t) || f.journalPresent(t) {
		t.Fatal("finalization left the original private key or the journal")
	}
	if _, err := f.store.Get(config.Service, f.slot.PublicAccount); err != nil {
		t.Fatal("finalization removed the archive public key")
	}
	if s := f.status(t); s.State != proto.ArchiveSplitStateNone {
		t.Fatalf("status after finalization = %+v", s)
	}
}

// The shares digest is rebuilt from the documented field list, independent of
// the proto helper, so a format change fails here.
func TestArchiveSplitSharesDigestFormat(t *testing.T) {
	f := newFinalizeFixture(t)
	var b strings.Builder
	b.WriteString("dragpass.archive.split.shares|1" + lp(strconv.Itoa(len(f.split.Shares))))
	for _, s := range f.split.Shares {
		b.WriteString(lp(strconv.Itoa(s.ShareIndex), proto.ArchiveShareEnvelopeDigest(s.ShareIndex, s.WrappedKey, s.Ciphertext), s.ProofPublicKey))
	}
	sum := sha256.Sum256([]byte(b.String()))
	if proto.ArchiveSplitSharesDigest(f.split.Shares) != hex.EncodeToString(sum[:]) {
		t.Fatal("shares digest format changed")
	}
	r := proto.ArchiveSplitFinalizationReceipt{OperationID: "o", OrgID: "g", ArchiveKeySPKIFingerprint: "s", ConfigDigest: "c", SharesDigest: "d", FinalizedAt: 7, ServerKeyVersion: 2}
	if got := proto.ArchiveSplitFinalizationReceiptCanonical(r); got != "dragpass.archive.split.finalized|1|1:o|1:g|1:s|1:c|1:d|1:7|1:2" {
		t.Fatalf("finalization receipt canonical = %q", got)
	}
	c := proto.ArchiveSplitClosureReceipt{OperationID: "o", OrgID: "g", Status: "cancelled", ArchiveKeySPKIFingerprint: "s", ServerKeyVersion: 2}
	if got := proto.ArchiveSplitClosureReceiptCanonical(c); got != "dragpass.archive.split.closed|1|1:o|1:g|9:cancelled|1:s|1:2" {
		t.Fatalf("closure receipt canonical = %q", got)
	}
}

func TestArchiveSplitFinalizeRefusesMismatchedReceiptAndKeepsKey(t *testing.T) {
	other := strings.Repeat("ab", 32)
	cases := map[string]func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest{
		"missing": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return proto.ArchiveSplitFinalizeRequest{OrgID: f.v.OrgID}
		},
		"forged": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			req := f.receipt(t, nil)
			req.Receipt.Signature = "AA=="
			return req
		},
		"other domain": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			req := f.receipt(t, nil)
			req.Receipt.Signature = f.sign(t, proto.ArchiveSplitClosureReceiptCanonical(proto.ArchiveSplitClosureReceipt{}))
			return req
		},
		"operation": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return f.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.OperationID = splitTestOther })
		},
		"org": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return f.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.OrgID = splitTestOther })
		},
		"request org": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			req := f.receipt(t, nil)
			req.OrgID = splitTestOther
			return req
		},
		"config digest": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return f.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.ConfigDigest = other })
		},
		"shares digest": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return f.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.SharesDigest = other })
		},
		"archive key": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitFinalizeRequest {
			return f.receipt(t, func(r *proto.ArchiveSplitFinalizationReceipt) { r.ArchiveKeySPKIFingerprint = other })
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFinalizeFixture(t)
			r := HandleArchiveSplitFinalize(f.deps, build(t, f))
			if r.Success || r.Data != nil {
				t.Fatal("mismatched finalization receipt was accepted")
			}
			if f.probe.deletes != 0 || f.probe.sets != 0 || !f.privatePresent(t) || !f.journalPresent(t) {
				t.Fatal("refused finalization changed the key or the journal")
			}
		})
	}
}

// After the split, the org rotated to a newer archive key. A receipt for the
// split must never delete that newer key.
func TestArchiveSplitFinalizeNeverDeletesNewerKey(t *testing.T) {
	f := newFinalizeFixture(t)
	req := f.receipt(t, nil)
	f.deps.Store = f.store
	beginOrg(t, f.deps, f.v.OrgID)
	if r := HandleArchiveKeyRotateCommit(f.deps, proto.ArchiveKeyRotateCommitRequest{OrgID: f.v.OrgID}); !r.Success {
		t.Fatalf("rotate: %s", r.Error)
	}
	_, newer, found, err := keychain.FindArchiveKey(f.store, keychain.OrgArchiveActiveCandidates(f.v.OrgID))
	if err != nil || !found || newer == f.archive {
		t.Fatal("rotation did not install a newer key")
	}
	slot, _, _, _ := keychain.FindArchiveKey(f.store, keychain.OrgArchiveActiveCandidates(f.v.OrgID))
	before, err := f.store.Get(config.Service, slot.PrivateAccount)
	if err != nil {
		t.Fatal(err)
	}
	f.deps.Store = f.probe
	f.resetProbe()
	if r := HandleArchiveSplitFinalize(f.deps, req); r.Success || r.Data != nil {
		t.Fatal("finalization accepted a receipt for a replaced key")
	}
	after, err := f.store.Get(config.Service, slot.PrivateAccount)
	if err != nil || after != before || f.probe.deletes != 0 {
		t.Fatal("finalization deleted or changed the newer archive key")
	}
}

func TestArchiveSplitFinalizeCleanupPendingThenRetryCompletes(t *testing.T) {
	f := newFinalizeFixture(t)
	failures := 1
	f.probe.deleteHook = func(account string) error {
		if f.probe.private[account] && failures > 0 {
			failures--
			return errors.New("keychain unavailable")
		}
		return nil
	}
	req := f.receipt(t, nil)
	r := HandleArchiveSplitFinalize(f.deps, req)
	if r.Success || r.ErrorCode != string(errs.ErrCodeArchiveSplitCleanupPending) {
		t.Fatalf("failed deletion answer = %+v", r)
	}
	if !f.privatePresent(t) || !f.journalPresent(t) {
		t.Fatal("failed deletion lost the key or the journal")
	}
	if s := f.status(t); s.State != proto.ArchiveSplitStateCleanupPending || s.OperationID != splitTestOperation {
		t.Fatalf("status after failed deletion = %+v", s)
	}
	if again := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request)); again.Success {
		t.Fatal("split retry returned shares while deletion was pending")
	}
	if r := HandleArchiveSplitFinalize(f.deps, req); !r.Success {
		t.Fatalf("finalization retry refused: %s %s", r.ErrorCode, r.Error)
	}
	if f.privatePresent(t) || f.journalPresent(t) {
		t.Fatal("retry did not complete the deletion")
	}
}

// A journal delete that fails after the key is gone is still cleanup pending,
// and the retry completes without the key.
func TestArchiveSplitFinalizeJournalDeleteFailureRetries(t *testing.T) {
	f := newFinalizeFixture(t)
	failures := 1
	f.probe.deleteHook = func(account string) error {
		if strings.HasPrefix(account, "archive_quorum_split_pending:") && failures > 0 {
			failures--
			return errors.New("keychain unavailable")
		}
		return nil
	}
	req := f.receipt(t, nil)
	if r := HandleArchiveSplitFinalize(f.deps, req); r.Success || r.ErrorCode != string(errs.ErrCodeArchiveSplitCleanupPending) {
		t.Fatalf("failed journal deletion answer = %+v", r)
	}
	if f.privatePresent(t) || !f.journalPresent(t) {
		t.Fatal("unexpected state after failed journal deletion")
	}
	if r := HandleArchiveSplitFinalize(f.deps, req); !r.Success || f.journalPresent(t) {
		t.Fatal("retry did not complete")
	}
}

func TestArchiveSplitConcurrentFinalizeDeletesOnce(t *testing.T) {
	f := newFinalizeFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	first := true
	f.probe.deleteHook = func(account string) error {
		if f.probe.private[account] && first {
			first = false
			close(entered)
			<-release
		}
		return nil
	}
	req := f.receipt(t, nil)
	results := make(chan proto.BaseResponse, 2)
	go func() { results <- HandleArchiveSplitFinalize(f.deps, req) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first finalization did not reach deletion")
	}
	go func() { results <- HandleArchiveSplitFinalize(f.deps, req) }()
	var early *proto.BaseResponse
	select {
	case r := <-results:
		early = &r
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	successes := 0
	collected := 0
	if early != nil {
		collected++
		if early.Success {
			successes++
		}
	}
	for ; collected < 2; collected++ {
		select {
		case r := <-results:
			if r.Success {
				successes++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("finalization did not finish")
		}
	}
	if early != nil && early.Success {
		t.Fatal("second finalization finished while the first was deleting")
	}
	f.probe.mu.Lock()
	defer f.probe.mu.Unlock()
	if successes != 1 || f.probe.privateDeletes != 1 {
		t.Fatalf("concurrent finalization: successes=%d private deletes=%d", successes, f.probe.privateDeletes)
	}
}

func TestArchiveSplitStatusReportsStateWithoutSecrets(t *testing.T) {
	f := newSplitFixture(t)
	none := HandleArchiveSplitStatus(f.deps, proto.ArchiveSplitStatusRequest{OrgID: f.v.OrgID})
	if !none.Success || none.Data.(proto.ArchiveSplitStateResponseData).State != proto.ArchiveSplitStateNone {
		t.Fatalf("status before split = %+v", none)
	}
	if r := HandleArchiveKeySplit(f.deps, f.authorize(t, f.request)); !r.Success {
		t.Fatal(r.Error)
	}
	f.resetProbe()
	r := HandleArchiveSplitStatus(f.deps, proto.ArchiveSplitStatusRequest{OrgID: f.v.OrgID})
	got := r.Data.(proto.ArchiveSplitStateResponseData)
	if !r.Success || got.State != proto.ArchiveSplitStatePrepared || got.OperationID != splitTestOperation {
		t.Fatalf("status after split = %+v", r)
	}
	encoded, _ := json.Marshal(r.Data)
	var fields map[string]any
	if json.Unmarshal(encoded, &fields) != nil || len(fields) != 2 {
		t.Fatalf("status carries more than state and operation: %s", encoded)
	}
	if f.probe.privateReads != 0 || f.probe.sets != 0 || f.probe.deletes != 0 {
		t.Fatal("status read a private key or wrote")
	}
	if bad := HandleArchiveSplitStatus(f.deps, proto.ArchiveSplitStatusRequest{OrgID: "x"}); bad.Success {
		t.Fatal("status accepted an invalid org id")
	}
}

func TestArchiveSplitAbandonDropsJournalAndKeepsKey(t *testing.T) {
	for _, status := range []string{proto.ArchiveSplitClosedCancelled, proto.ArchiveSplitClosedExpired, proto.ArchiveSplitClosedInvalidated} {
		t.Run(status, func(t *testing.T) {
			f := newFinalizeFixture(t)
			r := HandleArchiveSplitAbandon(f.deps, f.closure(t, func(c *proto.ArchiveSplitClosureReceipt) { c.Status = status }))
			if !r.Success {
				t.Fatalf("valid closure refused: %s %s", r.ErrorCode, r.Error)
			}
			if f.journalPresent(t) || !f.privatePresent(t) || f.probe.privateDeletes != 0 {
				t.Fatal("abandon did not drop only the journal")
			}
			if s := f.status(t); s.State != proto.ArchiveSplitStateNone {
				t.Fatalf("status after abandon = %+v", s)
			}
		})
	}
}

func TestArchiveSplitAbandonRefusesMismatchedClosure(t *testing.T) {
	cases := map[string]func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest{
		"missing": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			return proto.ArchiveSplitAbandonRequest{OrgID: f.v.OrgID}
		},
		"forged": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			req := f.closure(t, nil)
			req.Receipt.Signature = "AA=="
			return req
		},
		"finalized status": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			return f.closure(t, func(c *proto.ArchiveSplitClosureReceipt) { c.Status = "finalized" })
		},
		"operation": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			return f.closure(t, func(c *proto.ArchiveSplitClosureReceipt) { c.OperationID = splitTestOther })
		},
		"org": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			return f.closure(t, func(c *proto.ArchiveSplitClosureReceipt) { c.OrgID = splitTestOther })
		},
		"archive key": func(t *testing.T, f *finalizeFixture) proto.ArchiveSplitAbandonRequest {
			return f.closure(t, func(c *proto.ArchiveSplitClosureReceipt) { c.ArchiveKeySPKIFingerprint = strings.Repeat("ab", 32) })
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFinalizeFixture(t)
			if r := HandleArchiveSplitAbandon(f.deps, build(t, f)); r.Success {
				t.Fatal("mismatched closure receipt was accepted")
			}
			if !f.journalPresent(t) || f.probe.deletes != 0 {
				t.Fatal("refused abandon changed the journal")
			}
		})
	}
}

// Once deletion started, the server finalized; a closure receipt cannot
// restore the preparation.
func TestArchiveSplitAbandonRefusedAfterDeletionStarted(t *testing.T) {
	f := newFinalizeFixture(t)
	failures := 1
	f.probe.deleteHook = func(account string) error {
		if f.probe.private[account] && failures > 0 {
			failures--
			return errors.New("keychain unavailable")
		}
		return nil
	}
	if r := HandleArchiveSplitFinalize(f.deps, f.receipt(t, nil)); r.ErrorCode != string(errs.ErrCodeArchiveSplitCleanupPending) {
		t.Fatalf("setup: %+v", r)
	}
	if r := HandleArchiveSplitAbandon(f.deps, f.closure(t, nil)); r.Success || !f.journalPresent(t) {
		t.Fatal("abandon dropped a journal whose deletion had started")
	}
}
