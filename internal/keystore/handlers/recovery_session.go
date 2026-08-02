// Recovery private keys stay behind opaque session handles.

package handlers

import (
	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleRecoverySessionOpen unwraps the recovery PEM into memguard after
// verifying the server challenge signature.
func HandleRecoverySessionOpen(d Deps, req proto.RecoverySessionOpenRequest) proto.BaseResponse {
	d.Logger.Println("recovery session open request processing...")

	// Validate returns *ValidationError → CodeForError maps it to ErrCodeValidation.
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "recovery session open"); !ok {
		return resp
	}

	// decode wrap_key (raw 32B AES-GCM key)
	wrapKey, resp, ok := decodeBase64Len(req.WrapKeyB64, 32, "wrap_key")
	if !ok {
		d.Logger.Printf("recovery session open error: %s", resp.Error)
		return resp
	}
	wrapKeyBuf := memguard.NewBufferFromBytes(wrapKey)
	defer wrapKeyBuf.Destroy()
	return openRecoverySessionWithWrapKey(d, req.WrappedKeeperB64, wrapKeyBuf)
}

func openRecoverySessionWithWrapKey(d Deps, wrappedKeeperB64 string, wrapKey *memguard.LockedBuffer) proto.BaseResponse {

	// AES-GCM decrypt wrappedKeeper → raw PEM bytes
	pemBytes, err := crypto.AESGCMDecryptBase64(wrapKey.Bytes(), wrappedKeeperB64)
	if err != nil {
		d.Logger.Printf("recovery session open error: AES-GCM unwrap failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "wrapped keeper decrypt failed (wrong wrap key?): "+err.Error())
	}

	handle, expiresAt, openErr := d.RecoverySessions.Open(pemBytes)
	if openErr != nil {
		secure.Zeroize(pemBytes)
		d.Logger.Printf("recovery session open error: store.Open failed: %v", openErr)
		return errs.CodeResponse(errs.ErrCodeInternal, "store open failed: "+openErr.Error())
	}

	d.Logger.Println("recovery session open successful")
	return proto.BaseResponse{Success: true, Data: proto.RecoverySessionOpenResponseData{
		RecoveryHandle: handle,
		ExpiresAtMs:    expiresAt.UnixMilli(),
	}}
}

// HandleRecoverySessionClose explicitly discards the handle. Idempotent.
func HandleRecoverySessionClose(d Deps, req proto.RecoverySessionCloseRequest) proto.BaseResponse {
	d.Logger.Println("recovery session close request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	d.RecoverySessions.Close(req.RecoveryHandle)
	d.Logger.Println("recovery session close successful")
	return proto.BaseResponse{Success: true, Data: proto.RecoverySessionCloseResponseData{}}
}
