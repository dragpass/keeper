// group_dek.go — Group DEK RSA rewrap handler.
// HandleDEKRewrapWithOldKey — the Recovery rewrap composite action routed by
// the dispatcher.

package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleDEKRewrapWithOldKey is the Recovery rewrap composite action.
func HandleDEKRewrapWithOldKey(d Deps, req proto.DEKRewrapWithOldKeyRequest) proto.BaseResponse {
	d.Logger.Println("dek rewrap with old key request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// 1. Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "rewrap with old key"); !ok {
		return resp
	}

	// 2. decode ciphertext
	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedGroupDEK)
	if err != nil {
		d.Logger.Printf("rewrap with old key error: failed to decode encrypted_group_dek: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted_group_dek: "+err.Error())
	}

	// 3. parse new public key (before using the handle — fail-fast)
	newPubKey, err := crypto.ParsePublicKey(req.NewPublicKey)
	if err != nil {
		d.Logger.Printf("rewrap with old key error: failed to parse new public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse new public key: "+err.Error())
	}

	// 4. access PEM inside memguard via recovery_handle → unwrap → rewrap
	var newEncrypted []byte
	useErr := d.RecoverySessions.Use(req.RecoveryHandle, func(rawPEM []byte) error {
		oldPrivKey, err := crypto.ParsePrivateKey(string(rawPEM))
		if err != nil {
			return errors.New("failed to parse old private key: " + err.Error())
		}

		// RSA-OAEP decrypt → raw Group DEK 32B
		groupDEK, err := crypto.DecryptData(oldPrivKey, encrypted)
		if err != nil {
			return errors.New("RSA-OAEP decrypt failed: " + err.Error())
		}
		defer secure.Zeroize(groupDEK)

		if len(groupDEK) != 32 {
			return fmt.Errorf("unexpected group dek length: %d (want 32)", len(groupDEK))
		}

		ne, err := crypto.EncryptData(newPubKey, groupDEK)
		if err != nil {
			return errors.New("RSA-OAEP encrypt failed: " + err.Error())
		}
		newEncrypted = ne
		return nil
	})
	if useErr != nil {
		return recoverySessionUseError(useErr, "dek rewrap")
	}

	newEncryptedB64 := base64.StdEncoding.EncodeToString(newEncrypted)
	d.Logger.Println("dek rewrap with old key successful (raw group dek + old pem never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.DEKRewrapWithOldKeyResponseData{
		NewEncryptedGroupDEK: newEncryptedB64,
	}}
}
