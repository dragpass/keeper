package handlers

import (
	"errors"
	"strings"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

type archiveSessionOwner struct {
	account     string
	generation  uint64
	fingerprint string
}

var (
	errArchiveSessionLogin        = errors.New("archive session login unavailable")
	errArchiveSessionOtherOwner   = errors.New("archive session belongs to another account")
	errArchiveSessionUnknownOwner = errors.New("archive session owner unknown")
)

// archiveSessionCaller checks the Keeper-local account binding under the slot
// lock. Combine also checks the account independently signed by the server.
func archiveSessionCaller(d Deps, slot archiveSessionSlot) (archiveSessionOwner, error) {
	var owner archiveSessionOwner
	b, err := activeArchiveBinding(d)
	if err != nil {
		return owner, err
	}
	pub, err := keychain.GetPublicKey(d.Store)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return owner, errArchiveSessionLogin
	}
	if err != nil {
		return owner, err
	}
	if pub == "" {
		return owner, errArchiveSessionLogin
	}
	owner = archiveSessionOwner{account: b.AccountID, generation: b.Generation, fingerprint: crypto.AccountKeyFingerprint([]byte(pub))}
	switch {
	case slot.preserveUnknownOwner:
		return owner, errArchiveSessionUnknownOwner
	case slot.record.owner.account == "":
		return owner, nil
	case slot.record.owner.account != owner.account:
		return owner, errArchiveSessionOtherOwner
	case slot.record.owner != owner:
		return owner, errArchiveSessionLogin
	}
	return owner, nil
}

func activeArchiveBinding(d Deps) (keychain.AccountBinding, error) {
	b, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		return keychain.AccountBinding{}, err
	}
	if !found || b.SignedOut || b.Generation == 0 || !isLowerUUID(b.AccountID) {
		return keychain.AccountBinding{}, errArchiveSessionLogin
	}
	if expected := d.ArchiveRequestLogin; expected != nil && (b.AccountID != expected.AccountID || b.ChatStateGeneration != expected.Generation) {
		return keychain.AccountBinding{}, errArchiveSessionLogin
	}
	login, err := keychain.ReadChatLogin(d.Store)
	if err != nil {
		return keychain.AccountBinding{}, err
	}
	if (proto.ArchiveLoginIdentity{AccountID: b.AccountID, Generation: b.ChatStateGeneration}).Validate() != nil {
		return keychain.AccountBinding{}, errArchiveSessionLogin
	}
	if login.Committing || (login.Generation != "" && (login.AccountID != b.AccountID || login.Generation != b.ChatStateGeneration)) {
		return keychain.AccountBinding{}, errArchiveSessionLogin
	}
	ended, err := archiveLoginEnded(d, b)
	if err != nil {
		return keychain.AccountBinding{}, err
	}
	if ended {
		return keychain.AccountBinding{}, errArchiveSessionLogin
	}
	return b, nil
}

func archiveOwnerRefusal(err error) proto.BaseResponse {
	switch {
	case errors.Is(err, errArchiveSessionLogin):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionLoginUnavailable, errArchiveSessionLogin.Error())
	case errors.Is(err, errArchiveSessionOtherOwner):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionOtherOwner, errArchiveSessionOtherOwner.Error())
	case errors.Is(err, errArchiveSessionUnknownOwner):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionOwnerUnknown, errArchiveSessionUnknownOwner.Error())
	default:
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session owner failed")
	}
}

// Only the most recently ended login is needed. Binding generations are fresh
// on sign-in and delayed requests compare the captured incarnation under lock.
const archiveEndedLoginSlot = "archive_app_ended_login_v1"

func archiveLoginEnded(d Deps, b keychain.AccountBinding) (bool, error) {
	value, err := d.Store.Get(config.Service, archiveEndedLoginSlot)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	account, generation, found := strings.Cut(value, "|")
	if !found || (proto.ArchiveLoginIdentity{AccountID: account, Generation: generation}).Validate() != nil {
		return false, errors.New("invalid ended login record")
	}
	return account == b.AccountID && generation == b.ChatStateGeneration, nil
}

func HandleArchiveAppLoginEnd(d Deps, req proto.ArchiveAppLoginEndRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	err := withArchiveSessionSlotLock(d, func() error {
		login, err := keychain.ReadChatLogin(d.Store)
		if err != nil {
			return err
		}
		if login.Committing {
			return errArchiveSessionLogin
		}
		if req.IntentID != "" {
			if login.IntentID != req.IntentID && login.PendingID != req.IntentID && req.AfterSequence != nil && login.PreparationSequence > *req.AfterSequence {
				// Prepare requires equality with the original sequence. This exact
				// intent can no longer be installed and is neither active nor pending.
				return nil
			}
			if login.IntentID != req.IntentID || login.AccountID != req.AccountID || login.Generation == "" {
				return errArchiveSessionLogin
			}
			req.Generation = login.Generation
		}
		b, found, err := keychain.GetAccountBinding(d.Store)
		if err != nil || !found || b.SignedOut || b.AccountID != req.AccountID || b.ChatStateGeneration != req.Generation {
			return err
		}
		ended, err := archiveLoginEnded(d, b)
		if err != nil || ended {
			return err
		}
		return d.Store.Set(config.Service, archiveEndedLoginSlot, req.AccountID+"|"+req.Generation)
	})
	if err != nil {
		return archiveOwnerRefusal(err)
	}
	return proto.BaseResponse{Success: true, Data: struct {
		Settled bool `json:"settled"`
	}{true}}
}
