package handlers

import (
	"context"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

func HandleAuthRecoveryBegin(d Deps, req proto.AuthRecoveryBeginRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.UserPresence == nil || !d.UserPresence.Capabilities().PromptSecret {
		return errs.CodeResponse(errs.ErrCodeUnsupported, userpresence.ErrUnavailable.Error())
	}
	if d.RecoveryKeySessions == nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "recovery key session store unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := d.UserPresence.PromptSecret(ctx, userpresence.SecretPrompt{
		Title:   "Recover DragPass Account",
		Message: "Enter the recovery key for this DragPass account.",
		Label:   "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return authUserPresenceError(err)
	}
	if result.Secret == nil {
		return errs.CodeResponse(errs.ErrCodeValidation, userpresence.ErrEmptySecret.Error())
	}
	defer result.Secret.Destroy()

	authSeed, wrapKey, err := recoverykey.Derive(result.Secret.Bytes(), req.Alias, recoverykey.Version)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}
	secure.Zeroize(wrapKey)

	keyCopy := append([]byte(nil), result.Secret.Bytes()...)
	handle, expiresAt, err := d.RecoveryKeySessions.Open(keyCopy)
	if err != nil {
		secure.Zeroize(keyCopy)
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}

	return proto.BaseResponse{Success: true, Data: proto.AuthRecoveryBeginResponseData{
		RecoveryAuthSeed:    authSeed,
		EnteredKeyHandle:    handle,
		EnteredKeyExpiresAt: expiresAt.UnixMilli(),
	}}
}

func HandleAuthRecoveryPrepare(d Deps, req proto.AuthRecoveryPrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.RecoveryKeySessions == nil || d.RecoverySessions == nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "recovery session store unavailable")
	}
	if ok, response := verifyServerSig(
		d,
		req.ChallengeToken,
		req.Signature,
		req.ServerKeyVersion,
		"app-first recovery prepare",
	); !ok {
		return response
	}

	enteredKey, response := recoveryKeyHandleBuffer(d, req.EnteredKeyHandle)
	if !response.Success {
		return response
	}
	defer enteredKey.Destroy()

	_, oldWrapKey, err := recoverykey.Derive(enteredKey.Bytes(), req.Alias, uint(req.RecoveryKeyVersion))
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}
	oldWrapKeyBuffer := memguard.NewBufferFromBytes(oldWrapKey)
	defer oldWrapKeyBuffer.Destroy()

	openResponse := openRecoverySessionWithWrapKey(d, req.WrappedKeeperB64, oldWrapKeyBuffer)
	if !openResponse.Success {
		return openResponse
	}
	openData := openResponse.Data.(proto.RecoverySessionOpenResponseData)
	keepRecoveryHandle := false
	defer func() {
		if !keepRecoveryHandle {
			d.RecoverySessions.Close(openData.RecoveryHandle)
		}
	}()

	signResponse := signRecoveryChallenge(d, req.ChallengeToken, openData.RecoveryHandle)
	if !signResponse.Success {
		return signResponse
	}
	oldSignature := signResponse.Data.(proto.RecoverySignResponseData).Signature

	newRecoveryKey, err := recoverykey.Generate(d.Random())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate new recovery key")
	}
	newAuthSeed, newWrapKey, err := recoverykey.Derive(newRecoveryKey, req.Alias, recoverykey.Version)
	if err != nil {
		secure.Zeroize(newRecoveryKey)
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to derive new recovery key material")
	}
	newWrapKeyBuffer := memguard.NewBufferFromBytes(newWrapKey)
	defer newWrapKeyBuffer.Destroy()

	newKeyHandle, newKeyExpiresAt, err := d.RecoveryKeySessions.Open(newRecoveryKey)
	if err != nil {
		secure.Zeroize(newRecoveryKey)
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to protect new recovery key")
	}
	keepNewKeyHandle := false
	defer func() {
		if !keepNewKeyHandle {
			d.RecoveryKeySessions.Close(newKeyHandle)
		}
	}()

	keypairResponse := generateKeypairWithRecoveryWrapKey(d, newWrapKeyBuffer)
	if !keypairResponse.Success {
		return keypairResponse
	}
	keypairData := keypairResponse.Data.(proto.GenerateKeypairWithRecoveryWrapResponseData)

	d.RecoveryKeySessions.Close(req.EnteredKeyHandle)
	keepRecoveryHandle = true
	keepNewKeyHandle = true
	return proto.BaseResponse{Success: true, Data: proto.AuthRecoveryPrepareResponseData{
		OldChallengeSignature: oldSignature,
		RecoveryHandle:        openData.RecoveryHandle,
		RecoveryExpiresAt:     openData.ExpiresAtMs,
		NewPublicKey:          keypairData.PublicKey,
		NewRecoveryAuthSeed:   newAuthSeed,
		NewWrappedKeeper:      keypairData.WrappedKeeper,
		NewRecoveryKeyVersion: recoverykey.Version,
		NewRecoveryKeyHandle:  newKeyHandle,
		NewRecoveryKeyExpires: newKeyExpiresAt.UnixMilli(),
	}}
}

func recoveryKeyHandleBuffer(d Deps, handle string) (*memguard.LockedBuffer, proto.BaseResponse) {
	var key *memguard.LockedBuffer
	if err := d.RecoveryKeySessions.Use(handle, func(raw []byte) error {
		key = memguard.NewBufferFromBytes(append([]byte(nil), raw...))
		return nil
	}); err != nil {
		return nil, sessionUseError(err, "recovery key")
	}
	return key, proto.BaseResponse{Success: true}
}
