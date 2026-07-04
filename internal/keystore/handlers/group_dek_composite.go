// group_dek_composite.go — raw-free composite actions on the Keeper side
// that keep the Group DEK out of the Extension JS heap during admin flows.
//
//   - HandleGroupDEKGenerateAndOpen: generate new raw 32B inside the Keeper →
//     register with GroupSessionStore → RSA-OAEP wrap with my public key. The
//     response carries only the handle + wrappedForMe. raw is not included.
//   - HandleDEKRewrapForMember: unwrap my wrapped DEK with the Keychain private
//     key → RSA-OAEP wrap with the other party's public key. The response
//     carries only wrappedForOther.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGroupDEKGenerateAndOpen generates a raw 32B Group DEK inside the
// Keeper, registers it with the GroupSessionStore, and simultaneously
// RSA-OAEP-wraps it with the caller's public key for return. The raw bytes
// are not included in the response and do not reside in the Extension JS heap.
func HandleGroupDEKGenerateAndOpen(d Deps, req proto.GroupDEKGenerateAndOpenRequest) proto.BaseResponse {
	d.Logger.Println("group dek generate and open request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	myPubKey, err := crypto.ParsePublicKey(req.MyPublicKey)
	if err != nil {
		d.Logger.Printf("group dek generate error: failed to parse my public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse my public key: "+err.Error())
	}

	rawDEK := make([]byte, 32)
	if err := d.FillRandom(rawDEK); err != nil {
		d.Logger.Printf("group dek generate error: rand failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "rand failed: "+err.Error())
	}

	encrypted, err := crypto.EncryptData(myPubKey, rawDEK)
	if err != nil {
		secure.Zeroize(rawDEK)
		d.Logger.Printf("group dek generate error: RSA-OAEP encrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP encrypt failed: "+err.Error())
	}

	handle, expiresAt, openErr := d.GroupSessions.Open(rawDEK)
	if openErr != nil {
		secure.Zeroize(rawDEK)
		d.Logger.Printf("group dek generate error: store.Open failed: %v", openErr)
		return errs.CodeResponse(errs.ErrCodeInternal, "store open failed: "+openErr.Error())
	}

	encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)
	d.Logger.Println("group dek generate and open successful (raw never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.GroupDEKGenerateAndOpenResponseData{
		GroupHandle:       handle,
		ExpiresAtMs:       expiresAt.UnixMilli(),
		EncryptedForMeB64: encryptedB64,
	}}
}

// HandleDEKRewrapForMember unwraps my wrapped Group DEK with the Keychain
// private key and rewraps it with the other party's public key.
func HandleDEKRewrapForMember(d Deps, req proto.DEKRewrapForMemberRequest) proto.BaseResponse {
	d.Logger.Println("dek rewrap for member request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	otherPubKey, err := crypto.ParsePublicKey(req.OtherPublicKey)
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: failed to parse other public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse other public key: "+err.Error())
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.WrappedForMeB64)
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: failed to decode wrapped_for_me_b64: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode wrapped_for_me_b64: "+err.Error())
	}

	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: failed to get private key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer privKeyBuf.Destroy()

	privKey, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: failed to parse private key: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse private key: "+err.Error())
	}

	groupDEK, err := crypto.DecryptData(privKey, encrypted)
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: RSA-OAEP decrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt failed: "+err.Error())
	}
	defer secure.Zeroize(groupDEK)

	if len(groupDEK) != 32 {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, errors.New("unexpected group dek length (want 32)").Error())
	}

	newEncrypted, err := crypto.EncryptData(otherPubKey, groupDEK)
	if err != nil {
		d.Logger.Printf("dek rewrap for member error: RSA-OAEP encrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP encrypt failed: "+err.Error())
	}

	newEncryptedB64 := base64.StdEncoding.EncodeToString(newEncrypted)
	d.Logger.Println("dek rewrap for member successful (raw group dek never left Keeper)")
	return proto.BaseResponse{Success: true, Data: proto.DEKRewrapForMemberResponseData{
		EncryptedForOtherB64: newEncryptedB64,
	}}
}
