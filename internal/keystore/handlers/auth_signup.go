package handlers

import (
	"encoding/base64"
	"errors"
	"unicode/utf8"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/recoverykey"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

const signupPasswordMinLength = 12

// HandleAuthSignupPrepare performs all signup operations that depend on the
// password or RK24. Native Messaging carries secret inputs into Keeper and
// returns only encrypted or public material.
func HandleAuthSignupPrepare(d Deps, req proto.AuthSignupPrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	// Every check runs before any write. A refused signup (a registered
	// device, a bad password or recovery key) leaves the keyring as it was;
	// the new keypair and DEK are written to pending slots only, and
	// save_session_code promotes them once the server accepted the signup.
	if response := signupAllowed(d); !response.Success {
		secure.WipeString(&req.Password)
		secure.WipeString(&req.RecoveryKey)
		return response
	}
	if req.Password == "" {
		return errs.CodeResponse(errs.ErrCodeValidation, "password is required in the app")
	}
	if utf8.RuneCountInString(req.Password) < signupPasswordMinLength {
		secure.WipeString(&req.Password)
		return errs.CodeResponse(errs.ErrCodeValidation, "password must be at least 12 characters")
	}
	passwordBuffer := memguard.NewBufferFromBytes([]byte(req.Password))
	secure.WipeString(&req.Password)
	defer passwordBuffer.Destroy()

	recoveryKeyBytes := []byte(req.RecoveryKey)
	secure.WipeString(&req.RecoveryKey)
	defer secure.Zeroize(recoveryKeyBytes)
	recoveryAuthSeed, wrapKey, err := recoverykey.Derive(recoveryKeyBytes, req.Alias, recoverykey.Version)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}
	defer secure.Zeroize(wrapKey)

	if response := ensureSignupDeviceKey(d); !response.Success {
		return response
	}
	dekData, response := generateAndWrapDual(d, passwordBuffer, keychain.SavePendingSignupDeviceWrappedDEK)
	if !response.Success {
		return response
	}

	signResponse := signAliasWithWrapKey(d, req.Alias, wrapKey)
	if !signResponse.Success {
		return signResponse
	}
	signData := signResponse.Data.(proto.SignAliasResponseData)
	if signData.WrappedKeeper == "" {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "recovery-wrapped private key missing")
	}

	return proto.BaseResponse{Success: true, Data: proto.AuthSignupPrepareResponseData{
		PasswordWrappedDEKB64: dekData.PasswordWrappedDEKB64,
		DeviceWrappedDEKB64:   dekData.DeviceWrappedDEKB64,
		RecoveryAuthSeed:      recoveryAuthSeed,
		RecoveryWrappedKeeper: signData.WrappedKeeper,
		RecoveryKeyVersion:    recoverykey.Version,
		Signature:             signData.Signature,
		PublicKey:             signData.PublicKey,
	}}
}

// signupAllowed is the registered-device check signAliasWithWrapKey also
// makes, run before anything is written.
func signupAllowed(d Deps) proto.BaseResponse {
	_, keyErr := keychain.GetPrivateKey(d.Store)
	_, sessionErr := keychain.GetSessionCode(d.Store)
	switch {
	case keyErr == nil && sessionErr == nil:
		return errs.CodeResponse(errs.ErrCodeValidation, "device already registered. this device has already been registered for signup")
	case keyErr == nil:
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair exists without session. please contact support or use account recovery")
	}
	return proto.BaseResponse{Success: true}
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

// HandleAuthRecoveryReissuePrepare derives the replacement recovery material
// and returns only the verifier seed and wrapped active private key.
func HandleAuthRecoveryReissuePrepare(d Deps, req proto.AuthRecoveryReissuePrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	recoveryKey := []byte(req.RecoveryKey)
	secure.WipeString(&req.RecoveryKey)
	defer secure.Zeroize(recoveryKey)
	authSeed, wrapKey, err := recoverykey.Derive(recoveryKey, req.Alias, recoverykey.Version)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}
	defer secure.Zeroize(wrapKey)

	wrappedKeeper, response := wrapActivePrivateKeyWithKey(d, wrapKey)
	if !response.Success {
		return response
	}

	return proto.BaseResponse{Success: true, Data: proto.AuthRecoveryReissuePrepareResponseData{
		RecoveryAuthSeed:      authSeed,
		RecoveryWrappedKeeper: wrappedKeeper,
		RecoveryKeyVersion:    recoverykey.Version,
	}}
}

// wrapActivePrivateKeyWithKey AES-GCM-wraps the current active Keeper privkey
// with wrapKey and returns the Base64 result. The keypair itself is unchanged
// — only the wrap key is swapped, which is what an RK24 re-issue needs.
//
// The plaintext PEM is moved into memguard and the original string wiped, so
// it lives on the Go heap as briefly as possible.
func wrapActivePrivateKeyWithKey(d Deps, wrapKey []byte) (string, proto.BaseResponse) {
	pemStr, err := keychain.GetPrivateKey(d.Store)
	if err != nil {
		d.Logger.Printf("wrap active private key error: keychain lookup: %v", err)
		return "", errs.CodeResponse(errs.ErrCodeStorageFailure,
			"active private key not found in keychain: "+err.Error())
	}
	if pemStr == "" {
		return "", errs.CodeResponse(errs.ErrCodeNotFound,
			"active private key empty in keychain")
	}

	privKeyBuf := memguard.NewBufferFromBytes([]byte(pemStr))
	secure.WipeString(&pemStr)
	defer privKeyBuf.Destroy()

	wrappedB64, err := crypto.AESGCMEncryptBase64(wrapKey, privKeyBuf.Bytes())
	if err != nil {
		d.Logger.Printf("wrap active private key error: AES-GCM wrap failed: %v", err)
		return "", errs.CodeResponse(errs.ErrCodeCryptoFailure,
			"AES-GCM wrap failed: "+err.Error())
	}
	return wrappedB64, proto.BaseResponse{Success: true}
}
