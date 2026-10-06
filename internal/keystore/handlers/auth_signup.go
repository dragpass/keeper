package handlers

import (
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
	// device, a bad password or recovery key, another signup already staged)
	// leaves the keyring as it was; the new keypair and DEK are written to
	// pending slots only, and save_session_code promotes them once the server
	// accepted the signup. The staged-signup check and the staging cannot
	// interleave with another request in this process: every handler runs
	// under App.requestMu (app.go).
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
	normalizedRecoveryKey, err := recoverykey.Normalize(recoveryKeyBytes)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "invalid recovery key")
	}
	defer secure.Zeroize(normalizedRecoveryKey)

	stagedPrivate, stagedPublic, staged, err := keychain.StagedSignupKeypair(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the staged signup")
	}
	if staged {
		// The server may already hold the staged key, so only the input that
		// staged it may be answered again; anything else must not replace it.
		if !signupInputMatches(d, stagedPublic, req.Alias, normalizedRecoveryKey, passwordBuffer) {
			secure.WipeString(&stagedPrivate)
			return errs.CodeResponse(errs.ErrCodeSignupPending, "a signup is already staged on this device")
		}
		return answerStagedSignup(d, req.Alias, stagedPrivate, stagedPublic, passwordBuffer, recoveryAuthSeed, wrapKey)
	}

	if _, response := ensureDeviceKey(d); !response.Success {
		return response
	}
	accountID, err := newSignupAccountID(d)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate signup account identity")
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
	// Written last: a prepare that stops before this leaves a staged key no
	// retry can match, which the App aborts or signs in with.
	record, err := newSignupInputRecord(d, signData.PublicKey, accountID, req.Alias, normalizedRecoveryKey, passwordBuffer)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to record the signup input")
	}
	if err := keychain.SavePendingSignupPrepareInput(d.Store, record); err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to record the signup input")
	}

	pendingPrivate, err := getPendingPrivateKeySecure(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to load the staged signup key")
	}
	enrollmentSignature, err := signDataSecure(
		pendingPrivate,
		proto.AccountKeyEnrollmentCanonical(accountID, crypto.AccountKeyFingerprint([]byte(signData.PublicKey))),
	)
	pendingPrivate.Destroy()
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "failed to sign the account enrollment")
	}
	return proto.BaseResponse{Success: true, Data: proto.AuthSignupPrepareResponseData{
		AccountID:             accountID,
		EnrollmentSignature:   enrollmentSignature,
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

// HandleAuthRecoveryReissuePrepare derives the replacement recovery material
// and returns only the verifier seed and wrapped active private key.
func HandleAuthRecoveryReissuePrepare(d Deps, req proto.AuthRecoveryReissuePrepareRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	// While a recovery is staged the active key is not the account's key any
	// more (the server may already hold the staged one), so a reissue would
	// hand the server the wrong private key under the new RK24.
	if staged, err := keychain.HasPendingRecoveryKeypair(d.Store); err != nil || staged {
		secure.WipeString(&req.RecoveryKey)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the recovery state")
		}
		return errs.CodeResponse(errs.ErrCodeAccountKeyStaged, "a recovery is not complete on this device")
	}
	// A signup the server accepted but save_session_code never promoted: the
	// sign-in promotes it, and only then is there an active key to wrap.
	if _, _, staged, err := keychain.StagedSignupKeypair(d.Store); err != nil || staged {
		secure.WipeString(&req.RecoveryKey)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read the signup state")
		}
		return errs.CodeResponse(errs.ErrCodeAccountKeyStaged, "a signup is not complete on this device")
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

	wrappedB64, err := crypto.AESGCMEncryptBase64(d.Random(), wrapKey, privKeyBuf.Bytes())
	if err != nil {
		d.Logger.Printf("wrap active private key error: AES-GCM wrap failed: %v", err)
		return "", errs.CodeResponse(errs.ErrCodeCryptoFailure,
			"AES-GCM wrap failed: "+err.Error())
	}
	return wrappedB64, proto.BaseResponse{Success: true}
}
