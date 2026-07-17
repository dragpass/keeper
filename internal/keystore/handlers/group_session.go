// group_session.go — Group DEK opaque handle handlers.
// HandleGroupSessionOpen / Close / Status — three actions routed by the dispatcher.
//
// The groupSessionUseError helper is also referenced by item_dek.go's AES
// family handlers — they share automatically within the same (handlers)
// package.

package handlers

import (
	"encoding/base64"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGroupSessionOpen unwraps a wrapped Group DEK with the Keychain's
// active private key, registers it with GroupSessionStore, and returns the
// handle ID.
func HandleGroupSessionOpen(d Deps, req proto.GroupSessionOpenRequest) proto.BaseResponse {
	d.Logger.Println("group session open request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(req.EncryptedGroupDEK)
	if err != nil {
		d.Logger.Printf("group session open error: failed to decode encrypted_group_dek: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode encrypted_group_dek: "+err.Error())
	}

	privKeyBuf, err := getPrivateKeySecure(d.Store)
	if err != nil {
		d.Logger.Printf("group session open error: failed to get private key: %v", err)
		return errs.Response(err) // ErrSecretNotFound → not_found
	}
	defer privKeyBuf.Destroy()

	privKey, err := crypto.ParsePrivateKey(string(privKeyBuf.Bytes()))
	if err != nil {
		d.Logger.Printf("group session open error: failed to parse private key: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to parse private key: "+err.Error())
	}

	rawDEK, err := crypto.DecryptData(privKey, encrypted)
	if err != nil {
		d.Logger.Printf("group session open error: RSA-OAEP decrypt failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "RSA-OAEP decrypt failed: "+err.Error())
	}
	if len(rawDEK) != 32 {
		secure.Zeroize(rawDEK)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "unexpected group dek length (want 32)")
	}

	handle, expiresAt, err := d.GroupSessions.Open(rawDEK)
	if err != nil {
		secure.Zeroize(rawDEK)
		d.Logger.Printf("group session open error: store.Open failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "store open failed: "+err.Error())
	}

	d.Logger.Println("group session open successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupSessionOpenResponseData{
		GroupHandle: handle,
		ExpiresAtMs: expiresAt.UnixMilli(),
	}}
}

// HandleGroupSessionClose explicitly discards the handle. Idempotent — a
// missing handle also returns success.
func HandleGroupSessionClose(d Deps, req proto.GroupSessionCloseRequest) proto.BaseResponse {
	d.Logger.Println("group session close request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	d.GroupSessions.Close(req.GroupHandle)
	d.Logger.Println("group session close successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupSessionCloseResponseData{}}
}

// HandleGroupSessionStatus returns handle existence + remaining TTL in ms.
func HandleGroupSessionStatus(d Deps, req proto.GroupSessionStatusRequest) proto.BaseResponse {
	d.Logger.Println("group session status request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	exists, remaining := d.GroupSessions.Status(req.GroupHandle)
	return proto.BaseResponse{Success: true, Data: proto.GroupSessionStatusResponseData{
		Exists:      exists,
		RemainingMs: remaining,
	}}
}

// groupSessionUseError delegates to the single sessionUseError helper.
// Backward-compat wrapper for caller compatibility — can be removed gradually.
func groupSessionUseError(err error, context string) proto.BaseResponse {
	return sessionUseError(err, context)
}
