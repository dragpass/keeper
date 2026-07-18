package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
	"github.com/dragpass/keeper/internal/keystore/userpresence"
)

const signupPasswordMinLength = 12

// HandleAuthSignupPrepare performs all signup operations that depend on the
// password or RK24. Native Messaging carries only the alias in and encrypted
// or public material plus an opaque RK24 display handle out.
func HandleAuthSignupPrepare(d Deps, req proto.AuthSignupPrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.UserPresence == nil || !d.UserPresence.Capabilities().PromptNewSecret {
		return errs.CodeResponse(errs.ErrCodeUnsupported, userpresence.ErrUnavailable.Error())
	}
	if d.RecoveryKeySessions == nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "recovery key session store unavailable")
	}
	if response := ensureSignupDeviceKey(d); !response.Success {
		return response
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	passwordResult, err := d.UserPresence.PromptNewSecret(ctx, userpresence.NewSecretPrompt{
		Title:             "Create DragPass Password",
		Message:           "Create a password for encrypting this DragPass account.",
		Label:             "New password",
		ConfirmationLabel: "Confirm password",
		Timeout:           2 * time.Minute,
	})
	if err != nil {
		return authUserPresenceError(err)
	}
	if passwordResult.Secret == nil || len(passwordResult.Secret.Bytes()) < signupPasswordMinLength {
		if passwordResult.Secret != nil {
			passwordResult.Secret.Destroy()
		}
		return errs.CodeResponse(errs.ErrCodeValidation, "password must be at least 12 characters")
	}
	defer passwordResult.Secret.Destroy()

	dekData, response := generateAndWrapDual(d, passwordResult.Secret)
	if !response.Success {
		return response
	}

	recoveryKeyBytes, err := recoverykey.Generate(d.Random())
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate recovery key")
	}
	recoveryAuthSeed, wrapKey, err := recoverykey.Derive(recoveryKeyBytes, req.Alias, recoverykey.Version)
	if err != nil {
		secure.Zeroize(recoveryKeyBytes)
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to derive recovery key material")
	}
	defer secure.Zeroize(wrapKey)

	recoveryKeyHandle, expiresAt, err := d.RecoveryKeySessions.Open(recoveryKeyBytes)
	if err != nil {
		secure.Zeroize(recoveryKeyBytes)
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to protect recovery key")
	}
	keepHandle := false
	defer func() {
		if !keepHandle {
			d.RecoveryKeySessions.Close(recoveryKeyHandle)
		}
	}()

	signResponse := signAliasWithWrapKey(d, req.Alias, wrapKey)
	if !signResponse.Success {
		return signResponse
	}
	signData := signResponse.Data.(proto.SignAliasResponseData)
	if signData.WrappedKeeper == "" {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "recovery-wrapped private key missing")
	}

	keepHandle = true
	return proto.BaseResponse{Success: true, Data: proto.AuthSignupPrepareResponseData{
		PasswordWrappedDEKB64: dekData.PasswordWrappedDEKB64,
		DeviceWrappedDEKB64:   dekData.DeviceWrappedDEKB64,
		RecoveryAuthSeed:      recoveryAuthSeed,
		RecoveryWrappedKeeper: signData.WrappedKeeper,
		RecoveryKeyVersion:    recoverykey.Version,
		RecoveryKeyHandle:     recoveryKeyHandle,
		RecoveryKeyExpiresAt:  expiresAt.UnixMilli(),
		Signature:             signData.Signature,
		PublicKey:             signData.PublicKey,
	}}
}

func ensureSignupDeviceKey(d Deps) proto.BaseResponse {
	stored, err := keychain.GetDeviceKey(d.Store)
	if err == nil && stored != "" {
		raw, decodeErr := base64.StdEncoding.DecodeString(stored)
		if decodeErr != nil || len(raw) != 32 {
			secure.Zeroize(raw)
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "stored device key is invalid")
		}
		secure.Zeroize(raw)
		return proto.BaseResponse{Success: true}
	}
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read device key")
	}

	raw := make([]byte, 32)
	if err := d.FillRandom(raw); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate device key")
	}
	defer secure.Zeroize(raw)
	if err := keychain.SaveDeviceKey(d.Store, base64.StdEncoding.EncodeToString(raw)); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to store device key")
	}
	return proto.BaseResponse{Success: true}
}

func HandleAuthRecoveryKeyShow(d Deps, req proto.AuthRecoveryKeyShowRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if d.UserPresence == nil || !d.UserPresence.Capabilities().ShowRecoveryKey {
		return errs.CodeResponse(errs.ErrCodeUnsupported, userpresence.ErrUnavailable.Error())
	}
	if d.RecoveryKeySessions == nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "recovery key session store unavailable")
	}

	var recoveryKey *memguard.LockedBuffer
	useErr := d.RecoveryKeySessions.Use(req.RecoveryKeyHandle, func(raw []byte) error {
		copyForPrompt := append([]byte(nil), raw...)
		recoveryKey = memguard.NewBufferFromBytes(copyForPrompt)
		return nil
	})
	if useErr != nil {
		return sessionUseError(useErr, "recovery key display")
	}
	defer recoveryKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := d.UserPresence.ShowRecoveryKey(ctx, userpresence.RecoveryKeyPrompt{
		Title:       "Save Your Recovery Key",
		Message:     "Store this key somewhere safe. DragPass cannot recover it for you.",
		RecoveryKey: recoveryKey,
		Timeout:     5 * time.Minute,
	}); err != nil {
		return authUserPresenceError(err)
	}

	d.RecoveryKeySessions.Close(req.RecoveryKeyHandle)
	return proto.BaseResponse{Success: true, Data: proto.AuthRecoveryKeyShowResponseData{}}
}

func authUserPresenceError(err error) proto.BaseResponse {
	switch {
	case errors.Is(err, userpresence.ErrUnavailable):
		return errs.CodeResponse(errs.ErrCodeUnsupported, err.Error())
	case errors.Is(err, userpresence.ErrEmptySecret), errors.Is(err, userpresence.ErrSecretMismatch):
		return errs.CodeResponse(errs.ErrCodeValidation, err.Error())
	default:
		return errs.CodeResponse(errs.ErrCodeInternal, err.Error())
	}
}
