package handlers

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestReconfigurationFinalizePromotesPublicAndClearsOnlyStage(t *testing.T) {
	f := newSplitFixture(t)
	req, target := f.authorizeReconfiguration(t)
	d := req.ReconfigurationDecision
	split := HandleArchiveKeySplit(f.deps, req)
	if !split.Success {
		t.Fatal(split.ErrorCode)
	}
	active := keychain.OrgArchiveActiveSlot(req.OrgID)
	if err := active.DeletePrivate(f.store); err != nil {
		t.Fatal(err)
	}
	r := proto.ArchiveSplitFinalizationReceipt{Kind: "reconfiguration", OperationID: req.OperationID, OrgID: req.OrgID, ArchiveKeySPKIFingerprint: d.ActiveKeySPKIFingerprint, TargetKeySPKIFingerprint: d.TargetKeySPKIFingerprint, SourceConfigDigest: d.SourceConfigDigest, ConfigDigest: d.ConfigDigest, SharesDigest: proto.ArchiveSplitSharesDigest(split.Data.(proto.ArchiveKeySplitResponseData).Shares), GrantsDigest: strings.Repeat("f", 64), FinalizedAt: 500, ServerKeyVersion: 1}
	call := func(r proto.ArchiveSplitFinalizationReceipt) proto.BaseResponse {
		r.Signature = f.sign(t, proto.ArchiveSplitFinalizationReceiptCanonical(r))
		return HandleArchiveSplitFinalize(f.deps, proto.ArchiveSplitFinalizeRequest{OrgID: req.OrgID, Receipt: &r})
	}
	wrong := r
	wrong.ConfigDigest = strings.Repeat("0", 64)
	f.resetProbe()
	if call(wrong).Success || f.probe.sets != 0 || f.probe.deletes != 0 {
		t.Fatal("mismatched receipt mutated state")
	}
	slot := keychain.OrgArchiveReconfigurationSlot(req.OrgID)
	f.probe.deleteHook = func(a string) error {
		if a == slot.PrivateAccount {
			return errors.New("simulated delete failure")
		}
		return nil
	}
	if got := call(r); got.ErrorCode != string(errs.ErrCodeArchiveSplitCleanupPending) {
		t.Fatal("interrupted finalize:", got.ErrorCode)
	}
	var privateDeletes atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	f.probe.deleteHook = func(account string) error {
		if account == slot.PrivateAccount && privateDeletes.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	r.Signature = f.sign(t, proto.ArchiveSplitFinalizationReceiptCanonical(r))
	results := make(chan proto.BaseResponse, 2)
	retry := func() {
		results <- HandleArchiveSplitFinalize(f.deps, proto.ArchiveSplitFinalizeRequest{OrgID: req.OrgID, Receipt: &r})
	}
	go retry()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("retry did not enter cleanup")
	}
	started := make(chan struct{})
	go func() { close(started); retry() }()
	<-started
	close(release)
	for range 2 {
		if got := <-results; !got.Success {
			t.Fatal(got.ErrorCode)
		}
	}
	if privateDeletes.Load() != 1 {
		t.Fatal("both retries deleted staged private material")
	}
	f.probe.deleteHook = nil
	if pub, err := active.GetPublic(f.store); err != nil || pub != target.PublicKey {
		t.Fatal("wrong active public key")
	}
	if _, err := slot.GetPrivate(f.store); !errors.Is(err, keychain.ErrSecretNotFound) {
		t.Fatal("staged private key survived")
	}
	f.resetProbe()
	if got := call(r); !got.Success || f.probe.sets != 0 || f.probe.deletes != 0 {
		t.Fatal("replay mutated state")
	}
	setSlotTestOwner(t, f.deps, splitTestOther)
	f.resetProbe()
	if got := call(r); got.Success || f.probe.sets != 0 || f.probe.deletes != 0 {
		t.Fatal("foreign account received or changed completion state")
	}
}
