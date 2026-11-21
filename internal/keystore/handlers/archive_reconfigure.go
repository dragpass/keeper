// archive_reconfigure.go — the Keeper side of a legacy quorum
// reconfiguration (lv90).
//
// The reconfiguration stages a new org archive key in its own slot
// (keychain.OrgArchiveReconfigurationSlot), beside the active key and the
// rotation stage, which it never reads or writes. The org's reconfiguration
// journal records the operation kind, the operation ID and the staged key's
// fingerprint.

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const archiveOperationKindReconfiguration = "reconfiguration"

// archiveReconfigurationJournal is the org's reconfiguration record. It holds
// no secret.
type archiveReconfigurationJournal struct {
	OwnerAccountID      string `json:"owner_account_id,omitempty"`
	OwnerDeviceID       string `json:"owner_device_id,omitempty"`
	UnregisteredCleanup string `json:"unregistered_cleanup,omitempty"`

	// A signed closure pins cleanup across failed deletes and prevents stage retries from generating a replacement.
	Closure              *proto.ArchiveSplitClosureReceipt `json:"closure,omitempty"`
	Kind                 string                            `json:"kind"`
	OperationID          string                            `json:"operation_id"`
	OrgID                string                            `json:"org_id"`
	TargetKeyFingerprint string                            `json:"target_key_fingerprint,omitempty"`
}

type stageOwner struct{ account, device, generation string }

func currentStageOwner(d Deps) (stageOwner, error) {
	b, err := activeArchiveBinding(d)
	if err != nil {
		return stageOwner{}, err
	}
	device, found, err := keychain.GetDeviceID(d.Store)
	if err != nil {
		return stageOwner{}, err
	}
	if !found {
		return stageOwner{}, errArchiveSessionLogin
	}
	return stageOwner{b.AccountID, device, b.ChatStateGeneration}, nil
}

func archiveReconfigurationJournalAccount(orgID string) string {
	return config.OrgArchiveReconfigurationJournalPrefix + orgID
}

func closedReconfigurationAccount(orgID, operationID string) string {
	return archiveReconfigurationJournalAccount(orgID) + ":closed:" + operationID
}

func writeArchiveReconfigurationJournal(store keychain.SecretStore, journal archiveReconfigurationJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return store.Set(config.Service, archiveReconfigurationJournalAccount(journal.OrgID), string(encoded))
}

// orgArchiveReconfigurationPending reports whether the org has a
// reconfiguration journal or any key material in its reconfiguration slot.
func orgArchiveReconfigurationPending(store keychain.SecretStore, orgID string) (bool, error) {
	_, err := store.Get(config.Service, archiveReconfigurationJournalAccount(orgID))
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, keychain.ErrSecretNotFound) {
		return false, err
	}
	pub, hasPriv, err := slotHalves(store, keychain.OrgArchiveReconfigurationSlot(orgID))
	if err != nil {
		return false, err
	}
	return pub != "" || hasPriv, nil
}

func refuseArchiveReconfigurationPending() proto.BaseResponse {
	return errs.CodeResponse(errs.ErrCodeArchiveReconfigurationPending, "the org has a reconfiguration journal of another operation")
}

// reconfigurationStageDecision reads the org's journal. decided is true when
// the state already answers the call.
func reconfigurationStageDecision(d Deps, req proto.ArchiveReconfigureStageRequest, owner stageOwner) (proto.BaseResponse, bool, error) {
	slot := keychain.OrgArchiveReconfigurationSlot(req.OrgID)
	if _, err := d.Store.Get(config.Service, closedReconfigurationAccount(req.OrgID, req.OperationID)); err == nil {
		return refuseArchiveReconfigurationPending(), true, nil
	} else if !errors.Is(err, keychain.ErrSecretNotFound) {
		return proto.BaseResponse{}, false, err
	}
	raw, err := d.Store.Get(config.Service, archiveReconfigurationJournalAccount(req.OrgID))
	if errors.Is(err, keychain.ErrSecretNotFound) {
		pub, hasPriv, err := slotHalves(d.Store, slot)
		if err != nil {
			return proto.BaseResponse{}, false, err
		}
		if pub != "" || hasPriv {
			// The journal is written before the key, so key material without
			// one was not left by a stage of any known operation.
			return errs.CodeResponse(errs.ErrCodeArchiveKeySlotIncomplete, "the reconfiguration slot holds a key no operation names"), true, nil
		}
		return proto.BaseResponse{}, false, nil
	}
	if err != nil {
		return proto.BaseResponse{}, false, err
	}
	var journal archiveReconfigurationJournal
	// A journal that does not parse names no operation this call can prove
	// is its own, so it is kept and the stage refused.
	if json.Unmarshal([]byte(raw), &journal) != nil ||
		journal.Kind != archiveOperationKindReconfiguration ||
		journal.OperationID != req.OperationID || journal.OrgID != req.OrgID || journal.Closure != nil || journal.UnregisteredCleanup != "" || journal.OwnerAccountID != owner.account || journal.OwnerDeviceID != owner.device {
		return refuseArchiveReconfigurationPending(), true, nil
	}
	pub, hasPriv, err := slotHalves(d.Store, slot)
	if err != nil {
		return proto.BaseResponse{}, false, err
	}
	if journal.TargetKeyFingerprint != "" && (!hasPriv || pub == "" || journal.TargetKeyFingerprint != fingerprintBase64Public(pub)) {
		return errs.CodeResponse(errs.ErrCodeArchiveKeySlotIncomplete, "completed stage has an incomplete or changed key"), true, nil
	}
	if pub != "" && hasPriv && journal.TargetKeyFingerprint == fingerprintBase64Public(pub) {
		return proto.BaseResponse{Success: true, Data: proto.ArchiveReconfigureStageResponseData{
			PublicKey: pub, Fingerprint: journal.TargetKeyFingerprint,
		}}, true, nil
	}
	return proto.BaseResponse{}, false, nil
}

// HandleArchiveReconfigureStage stages a new archive key for the org's
// reconfiguration operation and returns only its public key and fingerprint.
// No active key is required: a legacy quorum org may have none on this
// device.
//
// It follows the lv96 rules for org archive slot writers: the whole call
// holds archiveSplitPreparationMu; the RSA pair is generated outside the
// keychain process lock, and the journal re-check and the writes run inside
// it (lock order: the mutex, then the process lock).
//
// Journal states:
//   - none, and no key in the reconfiguration slot: a new pair is staged;
//   - none, but key material in the slot: refused (archive_key_slot_incomplete);
//   - another operation, another kind or unreadable: refused
//     (archive_reconfiguration_pending), nothing changed;
//   - this operation with its staged key present: that key is returned;
//   - this operation without a complete key (an interrupted stage): a new
//     pair replaces whatever the interrupted stage left.
func HandleArchiveReconfigureStage(d Deps, req proto.ArchiveReconfigureStageRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	archiveSplitPreparationMu.Lock()
	defer archiveSplitPreparationMu.Unlock()
	d.Logger.Println("archive reconfigure stage processing...")
	var owner stageOwner
	var decided bool
	var resp proto.BaseResponse
	if err := archiveSlotProcessLock(d.Store, func() error {
		var err error
		owner, err = currentStageOwner(d)
		if err != nil {
			resp = archiveOwnerRefusal(err)
			decided = true
			return nil
		}
		resp, decided, err = reconfigurationStageDecision(d, req, owner)
		return err
	}); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read reconfiguration journal failed")
	}
	if decided {
		return resp
	}
	keyPair, err := archiveKeyPairGenerator()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "archive key keygen failed")
	}
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	if err := archiveSlotProcessLock(d.Store, func() error {
		if current, err := currentStageOwner(d); err != nil {
			resp = archiveOwnerRefusal(err)
			return nil
		} else if current != owner {
			resp = refuseArchiveReconfigurationPending()
			return nil
		}
		decision, decided, err := reconfigurationStageDecision(d, req, owner)
		if err != nil {
			resp = errs.CodeResponse(errs.ErrCodeStorageFailure, "read reconfiguration journal failed")
			return nil
		}
		if decided {
			// Another process staged meanwhile; the new pair is dropped.
			resp = decision
			return nil
		}
		resp = writeReconfigurationStage(d, req, owner, privKeyBuf.Bytes(), keyPair.PublicKey)
		return nil
	}); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "archive key lock unavailable")
	}
	return resp
}

// writeReconfigurationStage writes the journal without a key first, then the
// pair, private first, then the journal naming the key. Every interruption
// leaves either nothing or a journal of this operation, which its retry
// completes; a failed public write removes the private half again.
func writeReconfigurationStage(d Deps, req proto.ArchiveReconfigureStageRequest, owner stageOwner, privatePEM []byte, publicPEM string) proto.BaseResponse {
	journal := archiveReconfigurationJournal{OwnerAccountID: owner.account, OwnerDeviceID: owner.device, Kind: archiveOperationKindReconfiguration, OperationID: req.OperationID, OrgID: req.OrgID}
	if err := writeArchiveReconfigurationJournal(d.Store, journal); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save reconfiguration journal failed")
	}
	slot := keychain.OrgArchiveReconfigurationSlot(req.OrgID)
	if err := slot.SavePrivate(d.Store, string(privatePEM)); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save reconfiguration private key failed")
	}
	if err := slot.SavePublic(d.Store, publicPEM); err != nil {
		if delErr := slot.DeletePrivate(d.Store); delErr != nil && !errors.Is(delErr, keychain.ErrSecretNotFound) {
			d.Logger.Println("archive reconfigure stage: removing the unpublished private key failed")
		}
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save reconfiguration public key failed")
	}
	journal.TargetKeyFingerprint = fingerprintBase64Public(publicPEM)
	if err := writeArchiveReconfigurationJournal(d.Store, journal); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "save reconfiguration journal failed")
	}
	d.Logger.Println("archive reconfigure stage: new org rsa keypair staged (active key and rotation stage untouched)")
	return proto.BaseResponse{Success: true, Data: proto.ArchiveReconfigureStageResponseData{PublicKey: publicPEM, Fingerprint: journal.TargetKeyFingerprint}}
}
