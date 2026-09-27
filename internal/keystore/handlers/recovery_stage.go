// Handlers that finish or abandon a recovery staged by auth_recovery_prepare.

package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAuthRecoveryAbort drops the staged recovery keypair once the server
// refused the recovery. Idempotent.
func HandleAuthRecoveryAbort(d Deps, req proto.AuthRecoveryAbortRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	discarded, err := keychain.DiscardPendingRecoveryKeypair(d.Store, req.NewPublicKey)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to discard the staged recovery")
	}
	return proto.BaseResponse{Success: true, Data: proto.AuthRecoveryAbortResponseData{Discarded: discarded}}
}

// HandleDEKRewrapWithOldKeyToSelf moves one group DEK grant from the key the
// recovery restored to this Keeper's active account key. It refuses while the
// recovery is still staged (the server has not accepted the new key) and when
// the active key is still the recovered one, so the old key cannot be used to
// wrap a grant anywhere but the account's own new key.
func HandleDEKRewrapWithOldKeyToSelf(d Deps, req proto.DEKRewrapWithOldKeyToSelfRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "rewrap to self"); !ok {
		return resp
	}
	staged, err := keychain.HasPendingRecoveryKeypair(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the recovery state")
	}
	if staged {
		return errs.CodeResponse(errs.ErrCodeValidation, "recovery is not complete: the server has not accepted the new key")
	}
	activePEM, err := keychain.GetPublicKey(d.Store)
	if err != nil {
		return errs.Response(err)
	}
	activeKey, err := crypto.ParsePublicKey(activePEM)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "active public key is unreadable")
	}
	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedGroupDEK)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted_group_dek")
	}

	errUnrotated := errors.New("the active key is still the key being recovered")
	var rewrapped []byte
	useErr := d.RecoverySessions.Use(req.RecoveryHandle, func(rawPEM []byte) error {
		oldKey, err := crypto.ParsePrivateKey(string(rawPEM))
		if err != nil {
			return errors.New("failed to parse old private key")
		}
		if oldKey.PublicKey.Equal(activeKey) {
			return errUnrotated
		}
		groupDEK, err := crypto.DecryptData(oldKey, encrypted)
		if err != nil {
			return errors.New("RSA-OAEP decrypt failed")
		}
		defer secure.Zeroize(groupDEK)
		if len(groupDEK) != 32 {
			return fmt.Errorf("unexpected group dek length: %d (want 32)", len(groupDEK))
		}
		rewrapped, err = crypto.EncryptData(activeKey, groupDEK)
		return err
	})
	if errors.Is(useErr, errUnrotated) {
		return errs.CodeResponse(errs.ErrCodeValidation, errUnrotated.Error())
	}
	if useErr != nil {
		return sessionUseError(useErr, "dek rewrap to self")
	}
	d.Logger.Println("dek rewrap to self successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKRewrapWithOldKeyResponseData{
		NewEncryptedGroupDEK: base64.StdEncoding.EncodeToString(rewrapped),
	}}
}
