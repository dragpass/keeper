// group_dek.go — Group DEK RSA wrap/unwrap handlers.
// HandleWrapGroupDEK / HandleUnwrapGroupDEK / HandleDEKRewrapWithOldKey —
// actions routed by the dispatcher. Group encrypt/decrypt + the Recovery
// rewrap composite action.

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

// HandleWrapGroupDEK is the Group DEK wrap handler for group encrypt/decrypt.
func HandleWrapGroupDEK(d Deps, req proto.WrapGroupDEKRequest) proto.BaseResponse {
	d.Logger.Println("wrap group dek request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// decode Group DEK plaintext (expects a 32B AES-GCM key)
	groupDEK, err := base64.StdEncoding.DecodeString(req.GroupDEKB64)
	if err != nil {
		d.Logger.Printf("wrap group dek error: failed to decode group_dek_b64: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode group_dek_b64: "+err.Error())
	}
	if len(groupDEK) != 32 {
		// also zeroize wrong-length buffer before returning
		secure.Zeroize(groupDEK)
		return errs.CodeResponse(errs.ErrCodeValidation, "group_dek must be 32 bytes (AES-256 key)")
	}
	defer secure.Zeroize(groupDEK)

	// parse recipient public key
	recipientPubKey, err := crypto.ParsePublicKey(req.RecipientPublicKey)
	if err != nil {
		d.Logger.Printf("wrap group dek error: failed to parse recipient public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse recipient public key: "+err.Error())
	}

	// wrap with RSA-OAEP-SHA256
	encrypted, err := crypto.EncryptData(recipientPubKey, groupDEK)
	if err != nil {
		d.Logger.Printf("wrap group dek error: RSA-OAEP encrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP encrypt failed: "+err.Error())
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)
	d.Logger.Println("wrap group dek successful")
	return proto.BaseResponse{Success: true, Data: proto.WrapGroupDEKResponseData{
		EncryptedGroupDEK: encryptedB64,
	}}
}

// HandleUnwrapGroupDEK decrypts encrypted_group_dek with my active private
// key from the Keychain and returns the raw Group DEK.
func HandleUnwrapGroupDEK(d Deps, req proto.UnwrapGroupDEKRequest) proto.BaseResponse {
	d.Logger.Println("unwrap group dek request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// decode ciphertext
	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedGroupDEK)
	if err != nil {
		d.Logger.Printf("unwrap group dek error: failed to decode encrypted_group_dek: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted_group_dek: "+err.Error())
	}

	// fetch my active private key PEM from Keychain and protect with memguard (secure_bridge helper)
	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("unwrap group dek error: failed to get private key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer privKeyBuf.Destroy()

	// parse PEM
	privKey, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		d.Logger.Printf("unwrap group dek error: failed to parse private key: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse private key: "+err.Error())
	}

	// RSA-OAEP decrypt
	groupDEK, err := crypto.DecryptData(privKey, encrypted)
	if err != nil {
		d.Logger.Printf("unwrap group dek error: RSA-OAEP decrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt failed: "+err.Error())
	}
	// schedule zeroize of the plaintext Group DEK until just before return
	defer secure.Zeroize(groupDEK)

	if len(groupDEK) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, fmt.Sprintf("unexpected group dek length: %d (want 32)", len(groupDEK)))
	}

	groupDEKB64 := base64.StdEncoding.EncodeToString(groupDEK)
	d.Logger.Println("unwrap group dek successful")
	return proto.BaseResponse{Success: true, Data: proto.UnwrapGroupDEKResponseData{
		GroupDEKB64: groupDEKB64,
	}}
}

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
