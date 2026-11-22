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

// Both archive locks are held. Record the signed facts before publication.
// A retry may already find the target active and either staged half gone.
func finalizeReconfiguration(d Deps, r proto.ArchiveSplitFinalizationReceipt) proto.BaseResponse {
	owner, err := currentStageOwner(d)
	if err != nil {
		return archiveOwnerRefusal(err)
	}
	normalized := r
	normalized.ServerKeyVersion = 0
	facts := proto.ArchiveSplitFinalizationReceiptCanonical(normalized)
	ownerFacts := owner.account + "|" + owner.device + "|" + facts
	marker := closedReconfigurationAccount(r.OrgID, r.OperationID)
	saved, err := d.Store.Get(config.Service, marker)
	closed := err == nil
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read completion marker failed")
	}
	if closed && saved != ownerFacts {
		return denyArchiveSplitReceipt()
	}
	success := proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: proto.ArchiveSplitStateFinalized, OperationID: r.OperationID}}
	stage, err := readStageJournal(d.Store, r.OrgID)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		if closed {
			return success
		}
		return denyArchiveSplitReceipt()
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read reconfiguration journal failed")
	}
	if closed && stage.OperationID != r.OperationID {
		return success
	}
	if !stageBelongsTo(stage, owner, r.OrgID) || stage.OperationID != r.OperationID || stage.UnregisteredCleanup != "" || stage.Closure != nil || (stage.Finalization != "" && stage.Finalization != facts) {
		return denyArchiveSplitReceipt()
	}
	target := keychain.OrgArchiveReconfigurationSlot(r.OrgID)
	pub, err := target.GetPublic(d.Store)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read target public key failed")
	}
	if pub != "" {
		spki, err := crypto.RewrapKeyFingerprint(pub)
		if err != nil || spki != r.TargetKeySPKIFingerprint || fingerprintBase64Public(pub) != stage.TargetKeyFingerprint {
			return denyArchiveSplitReceipt()
		}
	}
	active := keychain.OrgArchiveActiveSlot(r.OrgID)
	activePub, hasPrivate, err := slotHalves(d.Store, active)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read active key state failed")
	}
	if hasPrivate {
		return denyArchiveSplitReceipt()
	}
	if activePub != "" {
		spki, err := crypto.RewrapKeyFingerprint(activePub)
		if err != nil || (spki != r.ArchiveKeySPKIFingerprint && !(stage.Finalization == facts && spki == r.TargetKeySPKIFingerprint)) {
			return denyArchiveSplitReceipt()
		}
	}
	if stage.Finalization == "" {
		if pub == "" {
			return denyArchiveSplitReceipt()
		}
		raw, err := d.Store.Get(config.Service, archiveSplitJournalAccount(target))
		var split archiveSplitJournal
		if err != nil || json.Unmarshal([]byte(raw), &split) != nil {
			return denyArchiveSplitReceipt()
		}
		b := split.Binding
		if split.State != "" || split.OperationID != r.OperationID || b.Kind != r.Kind || b.OrgID != r.OrgID || b.AccountID != owner.account || b.ConfigDigest != r.ConfigDigest || b.SourceConfigDigest != r.SourceConfigDigest || b.ActiveKeySPKIFingerprint != r.ArchiveKeySPKIFingerprint || b.ArchiveKeySPKIFingerprint != r.TargetKeySPKIFingerprint || split.KeyFingerprint != stage.TargetKeyFingerprint || proto.ArchiveSplitSharesDigest(split.Result.Shares) != r.SharesDigest {
			return denyArchiveSplitReceipt()
		}
		stage.Finalization = facts
		if writeArchiveReconfigurationJournal(d.Store, stage) != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "record finalization failed")
		}
	}
	if fingerprintBase64Public(activePub) != stage.TargetKeyFingerprint {
		if pub == "" {
			return denyArchiveSplitReceipt()
		}
		if active.SavePublic(d.Store, pub) != nil {
			return errs.CodeResponse(errs.ErrCodeArchiveSplitCleanupPending, "publish finalized public key pending")
		}
	}
	return finishStageCleanup(d.Store, target, archiveReconfigurationJournalAccount(r.OrgID), marker, ownerFacts, closed, success)
}
