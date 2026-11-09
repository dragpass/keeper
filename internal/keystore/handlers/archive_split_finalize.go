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
	slot, activePublic, journal, found, err := readArchiveSplitJournal(d.Store, req.OrgID)
	if err != nil || !found {
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
	receipt := *req.Receipt
	if err := d.ServerKeyVerifier.Verify(proto.ArchiveSplitClosureReceiptCanonical(receipt), receipt.Signature, receipt.ServerKeyVersion); err != nil {
		return denyArchiveSplitReceipt()
	}
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()
	slot, _, journal, found, err := readArchiveSplitJournal(d.Store, req.OrgID)
	if err != nil || !found || journal.State != "" || journal.OperationID != receipt.OperationID ||
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
