// archive_split_finalize.go — the end of an archive split: finalization
// deletes the original org archive private key once the server's signed
// finalization receipt matches this Keeper's split journal and current key;
// abandonment drops the journal and keeps the key; status reports the
// journal state without secrets.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	archiveSplitJournalDeleting       = "deleting"
	archiveSplitJournalCleanupPending = "cleanup_pending"
)

func archiveSplitJournalAccount(slot keychain.ArchiveKeySlot) string {
	return "archive_quorum_split_pending:" + slot.PrivateAccount
}

// readArchiveSplitJournal returns the org's active slot, its public key and
// its journal. found is false when there is no active key or no journal.
func readArchiveSplitJournal(store keychain.SecretStore, orgID string) (keychain.ArchiveKeySlot, string, archiveSplitJournal, bool, error) {
	slot, activePublic, found, err := keychain.FindArchiveKey(store, keychain.OrgArchiveActiveCandidates(orgID))
	if err != nil || !found {
		return keychain.ArchiveKeySlot{}, "", archiveSplitJournal{}, false, err
	}
	raw, err := store.Get(config.Service, archiveSplitJournalAccount(slot))
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return slot, activePublic, archiveSplitJournal{}, false, nil
	}
	if err != nil {
		return keychain.ArchiveKeySlot{}, "", archiveSplitJournal{}, false, err
	}
	var journal archiveSplitJournal
	if err := json.Unmarshal([]byte(raw), &journal); err != nil {
		return keychain.ArchiveKeySlot{}, "", archiveSplitJournal{}, false, err
	}
	return slot, activePublic, journal, true, nil
}

func writeArchiveSplitJournal(store keychain.SecretStore, slot keychain.ArchiveKeySlot, journal archiveSplitJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return store.Set(config.Service, archiveSplitJournalAccount(slot), string(encoded))
}

// deleteSecretGone deletes an entry and reports success when it is absent
// afterwards, so a retry after a partly failed delete converges.
func deleteSecretGone(store keychain.SecretStore, account string) bool {
	if store.Delete(config.Service, account) == nil {
		return true
	}
	_, err := store.Get(config.Service, account)
	return errors.Is(err, keychain.ErrSecretNotFound)
}

func archiveSplitStateOf(journal archiveSplitJournal) string {
	switch journal.State {
	case "":
		return proto.ArchiveSplitStatePrepared
	case archiveSplitJournalDeleting:
		return proto.ArchiveSplitStateDeleting
	default:
		return proto.ArchiveSplitStateCleanupPending
	}
}

// HandleArchiveSplitStatus reports the org's split journal state and its
// operation ID. It reads public slots and the journal only.
func HandleArchiveSplitStatus(d Deps, req proto.ArchiveSplitStatusRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()
	if req.Kind == archiveOperationKindReconfiguration {
		return underStageLock(d.Store, func() proto.BaseResponse { return ownedStageStatus(d, req.OrgID) })
	}
	_, _, journal, found, err := readArchiveSplitJournal(d.Store, req.OrgID)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive split state failed")
	}
	if !found {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: proto.ArchiveSplitStateNone}}
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{
		State: archiveSplitStateOf(journal), OperationID: journal.OperationID,
	}}
}

func denyArchiveSplitReceipt() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeNotFound, "archive split receipt does not match this Keeper")
}

// HandleArchiveSplitFinalize deletes the original archive private key only
// when the signed finalization receipt names this Keeper's journaled
// operation, organization, configuration, share set and archive key, and the
// org's current public key is still the journaled one. The journal mutex is
// held from the journal read through deletion, so concurrent calls delete
// once. A failed deletion keeps the journal and answers cleanup_pending.
func HandleArchiveSplitFinalize(d Deps, req proto.ArchiveSplitFinalizeRequest) proto.BaseResponse {
	if d.Store == nil || d.ServerKeyVerifier == nil || req.Validate() != nil {
		return denyArchiveSplitReceipt()
	}
	receipt := *req.Receipt
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveSplitFinalizationReceiptCanonical(receipt), receipt.Signature, receipt.ServerKeyVersion); err != nil {
		return denyArchiveSplitReceipt()
	}
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()
	if receipt.Kind == archiveOperationKindReconfiguration {
		return underStageLock(d.Store, func() proto.BaseResponse { return finalizeReconfiguration(d, receipt) })
	}
	slot, activePublic, journal, found, err := readArchiveSplitJournal(d.Store, req.OrgID)
	// Only an org-scoped slot is ever deleted; the split gate refuses the
	// device-wide slot, and this repeats that check before any deletion.
	if err != nil || !found || slot.Scope != keychain.ArchiveScopeOrg {
		return denyArchiveSplitReceipt()
	}
	spki, err := crypto.RewrapKeyFingerprint(activePublic)
	if err != nil || journal.OperationID != receipt.OperationID || journal.Binding.OrgID != receipt.OrgID ||
		journal.Binding.ConfigDigest != receipt.ConfigDigest ||
		journal.Binding.ArchiveKeySPKIFingerprint != receipt.ArchiveKeySPKIFingerprint ||
		spki != receipt.ArchiveKeySPKIFingerprint ||
		journal.KeyFingerprint == "" || fingerprintBase64Public(activePublic) != journal.KeyFingerprint ||
		proto.ArchiveSplitSharesDigest(journal.Result.Shares) != receipt.SharesDigest {
		return denyArchiveSplitReceipt()
	}
	if journal.State == "" {
		journal.State = archiveSplitJournalDeleting
		if writeArchiveSplitJournal(d.Store, slot, journal) != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "record archive split deletion failed")
		}
	}
	cleanupPending := func() proto.BaseResponse {
		journal.State = archiveSplitJournalCleanupPending
		_ = writeArchiveSplitJournal(d.Store, slot, journal) // the journal stays either way
		d.Logger.Println("archive split finalize: deletion incomplete, cleanup pending")
		return errs.CodeResponse(errs.ErrCodeArchiveSplitCleanupPending, "archive key deletion pending; retry with the same receipt")
	}
	if !deleteSecretGone(d.Store, slot.PrivateAccount) {
		return cleanupPending()
	}
	if !deleteSecretGone(d.Store, archiveSplitJournalAccount(slot)) {
		return cleanupPending()
	}
	d.Logger.Println("archive split finalized: original archive private key deleted")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{
		State: proto.ArchiveSplitStateFinalized, OperationID: receipt.OperationID,
	}}
}

// HandleArchiveSplitAbandon drops a prepared split journal when the signed
// closure receipt names its operation, organization and archive key. The
// archive private key is kept. A journal whose deletion started is never
// abandoned: the server finalized that operation.
func HandleArchiveSplitAbandon(d Deps, req proto.ArchiveSplitAbandonRequest) proto.BaseResponse {
	if d.Store == nil || d.ServerKeyVerifier == nil || req.Validate() != nil {
		return denyArchiveSplitReceipt()
	}
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()
	if proof := req.UnregisteredClosure; proof != nil {
		if err := d.ServerKeyVerifier.Verify(proof.Canonical(), proof.Signature, proof.ServerKeyVersion); err != nil {
			return denyArchiveSplitReceipt()
		}
		return underStageLock(d.Store, func() proto.BaseResponse {
			return discardUnregisteredStage(d, *proof, req.ExpectedFingerprint, req.ExpectedLoginGeneration)
		})
	}
	receipt := *req.Receipt
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveSplitClosureReceiptCanonical(receipt), receipt.Signature, receipt.ServerKeyVersion); err != nil {
		return denyArchiveSplitReceipt()
	}
	if receipt.Kind == archiveOperationKindReconfiguration {
		return underStageLock(d.Store, func() proto.BaseResponse { return abandonReconfiguration(d.Store, receipt) })
	}
	slot, _, journal, found, err := readArchiveSplitJournal(d.Store, req.OrgID)
	if err != nil || !found || slot.Scope != keychain.ArchiveScopeOrg || journal.State != "" ||
		journal.OperationID != receipt.OperationID ||
		journal.Binding.OrgID != receipt.OrgID ||
		journal.Binding.ArchiveKeySPKIFingerprint != receipt.ArchiveKeySPKIFingerprint {
		return denyArchiveSplitReceipt()
	}
	if !deleteSecretGone(d.Store, archiveSplitJournalAccount(slot)) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "remove archive split preparation failed")
	}
	d.Logger.Println("archive split abandoned: journal removed, archive private key kept")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{
		State: proto.ArchiveSplitStateNone, OperationID: receipt.OperationID,
	}}
}

// abandonReconfiguration runs with both archive slot locks held. The stage
// journal is the last entry removed so a partial deletion can be resumed.
func abandonReconfiguration(store keychain.SecretStore, r proto.ArchiveSplitClosureReceipt) proto.BaseResponse {
	slot := keychain.OrgArchiveReconfigurationSlot(r.OrgID)
	account := archiveReconfigurationJournalAccount(r.OrgID)
	marker := closedReconfigurationAccount(r.OrgID, r.OperationID)
	facts := r
	facts.ServerKeyVersion = 0
	closedFacts := proto.ArchiveSplitClosureReceiptCanonical(facts)
	saved, err := store.Get(config.Service, marker)
	closed := err == nil
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staged closure failed")
	}
	if closed && saved != closedFacts {
		return denyArchiveSplitReceipt()
	}
	success := proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: proto.ArchiveSplitStateNone, OperationID: r.OperationID}}
	var stage archiveReconfigurationJournal
	raw, err := store.Get(config.Service, account)
	if err != nil {
		if !errors.Is(err, keychain.ErrSecretNotFound) {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage journal failed")
		}
		if closed {
			return success
		}
		return denyArchiveSplitReceipt()
	}
	if json.Unmarshal([]byte(raw), &stage) != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "invalid stage journal")
	}
	if closed && stage.OperationID != r.OperationID {
		return success
	}
	if stage.Finalization != "" || stage.UnregisteredCleanup != "" || stage.Kind != r.Kind || stage.OrgID != r.OrgID || stage.OperationID != r.OperationID || stage.TargetKeyFingerprint == "" {
		return denyArchiveSplitReceipt()
	}
	pub, err := slot.GetPublic(store)
	if err == nil {
		spki, e := crypto.RewrapKeyFingerprint(pub)
		if e != nil || spki != r.TargetKeySPKIFingerprint || fingerprintBase64Public(pub) != stage.TargetKeyFingerprint {
			return denyArchiveSplitReceipt()
		}
	} else if !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staged public key failed")
	} else if stage.Closure == nil {
		return denyArchiveSplitReceipt()
	}
	if stage.Closure == nil {
		raw, err = store.Get(config.Service, archiveSplitJournalAccount(slot))
		if err == nil {
			var split archiveSplitJournal
			if json.Unmarshal([]byte(raw), &split) != nil || split.State != "" || split.Binding.Kind != r.Kind || split.OperationID != r.OperationID || split.Binding.OrgID != r.OrgID || split.Binding.SourceConfigDigest != r.SourceConfigDigest || split.Binding.ArchiveKeySPKIFingerprint != r.TargetKeySPKIFingerprint || split.KeyFingerprint != stage.TargetKeyFingerprint {
				return denyArchiveSplitReceipt()
			}
		} else if !errors.Is(err, keychain.ErrSecretNotFound) {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staged split journal failed")
		}
		stage.Closure = &r
		if err := writeArchiveReconfigurationJournal(store, stage); err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "record staged cleanup failed")
		}
	} else {
		// A status reread can return the same facts signed by a newer server key.
		c := stage.Closure
		if c.Kind != r.Kind || c.OrgID != r.OrgID || c.OperationID != r.OperationID || c.Status != r.Status || c.TargetKeySPKIFingerprint != r.TargetKeySPKIFingerprint || c.SourceConfigDigest != r.SourceConfigDigest {
			return denyArchiveSplitReceipt()
		}
	}
	return finishStageCleanup(store, slot, account, marker, closedFacts, closed, success)
}

// Both closure formats persist their verified intent before the first delete.
func finishStageCleanup(store keychain.SecretStore, slot keychain.ArchiveKeySlot, account, marker, closedFacts string, closed bool, success proto.BaseResponse) proto.BaseResponse {
	pending := func() proto.BaseResponse {
		return errs.CodeResponse(errs.ErrCodeArchiveSplitCleanupPending, "staged key deletion pending")
	}
	for _, entry := range []string{slot.PrivateAccount, slot.PublicAccount, archiveSplitJournalAccount(slot)} {
		if err := store.Delete(config.Service, entry); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
			return pending()
		}
	}
	if !closed {
		if err := store.Set(config.Service, marker, closedFacts); err != nil {
			return pending()
		}
	}
	if err := store.Delete(config.Service, account); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return pending()
	}
	return success
}
