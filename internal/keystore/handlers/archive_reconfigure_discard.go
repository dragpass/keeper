package handlers

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func underStageLock(store keychain.SecretStore, fn func() proto.BaseResponse) proto.BaseResponse {
	var response proto.BaseResponse
	if err := archiveSlotProcessLock(store, func() error { response = fn(); return nil }); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "archive slot lock unavailable")
	}
	return response
}

func readStageJournal(store keychain.SecretStore, org string) (archiveReconfigurationJournal, error) {
	var stage archiveReconfigurationJournal
	raw, err := store.Get(config.Service, archiveReconfigurationJournalAccount(org))
	if err != nil {
		return stage, err
	}
	err = json.Unmarshal([]byte(raw), &stage)
	return stage, err
}

func stageBelongsTo(stage archiveReconfigurationJournal, owner stageOwner, org string) bool {
	return stage.Kind == archiveOperationKindReconfiguration && stage.OrgID == org && stage.OperationID != "" && stage.OwnerAccountID == owner.account && stage.OwnerDeviceID == owner.device && stage.Closure == nil && stage.TargetKeyFingerprint != ""
}

// The public half may already be gone on a retry of a recorded cleanup.
func checkStagePublic(store keychain.SecretStore, slot keychain.ArchiveKeySlot, stage archiveReconfigurationJournal) (bool, error) {
	pub, err := slot.GetPublic(store)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return stage.UnregisteredCleanup != "" || stage.Finalization != "", nil
	}
	if err != nil {
		return false, err
	}
	return fingerprintBase64Public(pub) == stage.TargetKeyFingerprint, nil
}

func ownedStageStatus(d Deps, org string) proto.BaseResponse {
	store := d.Store
	owner, err := currentStageOwner(d)
	if err != nil {
		return archiveOwnerRefusal(err)
	}
	stage, err := readStageJournal(store, org)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		_, pubErr := keychain.OrgArchiveReconfigurationSlot(org).GetPublic(store)
		if pubErr == nil {
			return errs.CodeResponse(errs.ErrCodeArchiveKeySlotIncomplete, "staged key without journal")
		}
		if !errors.Is(pubErr, keychain.ErrSecretNotFound) {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage public key failed")
		}
		return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: proto.ArchiveSplitStateNone}}
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage journal failed")
	}
	if !stageBelongsTo(stage, owner, org) {
		return denyArchiveSplitReceipt()
	}
	ok, err := checkStagePublic(store, keychain.OrgArchiveReconfigurationSlot(org), stage)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage public key failed")
	}
	if !ok {
		return denyArchiveSplitReceipt()
	}
	state := "key_staged"
	if stage.UnregisteredCleanup != "" || stage.Finalization != "" {
		state = proto.ArchiveSplitStateCleanupPending
	}
	return proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: state, Kind: stage.Kind, OperationID: stage.OperationID, Fingerprint: stage.TargetKeyFingerprint, LoginGeneration: owner.generation}}
}

func discardUnregisteredStage(d Deps, r proto.ArchiveUnregisteredClosure, expected, generation string) proto.BaseResponse {
	store := d.Store
	owner, err := currentStageOwner(d)
	if err != nil {
		return archiveOwnerRefusal(err)
	}
	if owner.generation != generation || owner.account != r.RequesterAccountID || owner.device != r.RequesterDeviceID {
		return denyArchiveSplitReceipt()
	}
	// Signer rotation preserves the terminal fact. The confirmation also
	// names the exact locally observed key, absent from the server statement.
	r.ServerKeyVersion = 0
	facts := r.Canonical() + "|64:" + expected
	marker := closedReconfigurationAccount(r.OrgID, r.OperationID)
	saved, err := store.Get(config.Service, marker)
	closed := err == nil
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staged closure failed")
	}
	if closed && saved != facts {
		return denyArchiveSplitReceipt()
	}
	success := proto.BaseResponse{Success: true, Data: proto.ArchiveSplitStateResponseData{State: proto.ArchiveSplitStateNone, OperationID: r.OperationID}}
	stage, err := readStageJournal(store, r.OrgID)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		if closed {
			return success
		}
		return denyArchiveSplitReceipt()
	}
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage journal failed")
	}
	if closed && stage.OperationID != r.OperationID {
		return success
	}
	if stage.Finalization != "" || !stageBelongsTo(stage, owner, r.OrgID) || stage.OperationID != r.OperationID || stage.TargetKeyFingerprint != expected || (stage.UnregisteredCleanup != "" && stage.UnregisteredCleanup != facts) {
		return denyArchiveSplitReceipt()
	}
	slot := keychain.OrgArchiveReconfigurationSlot(r.OrgID)
	ok, err := checkStagePublic(store, slot, stage)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read stage public key failed")
	}
	if !ok {
		return denyArchiveSplitReceipt()
	}
	// A split journal is positive evidence of registration. Keep all local
	// material if it contradicts the statement, including on cleanup retry.
	// An interrupted preparation (state "writing") was never returned and is
	// no such evidence; the cleanup removes it with the target.
	if split, found, err := loadArchiveSplitJournal(store, slot); err != nil && !errors.Is(err, errArchiveSplitJournalInconsistent) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read staged split journal failed")
	} else if found && (err != nil || split.State != archiveSplitJournalWriting) {
		return denyArchiveSplitReceipt()
	}
	if stage.UnregisteredCleanup == "" {
		stage.UnregisteredCleanup = facts
		if err := writeArchiveReconfigurationJournal(store, stage); err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "record staged cleanup failed")
		}
	}
	return finishStageCleanup(store, slot, archiveReconfigurationJournalAccount(r.OrgID), marker, facts, closed, success)
}
