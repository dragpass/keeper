// recovery.go — recovery flow handlers.
// HandleRecoverySign / HandleGenerateKeypairWithRecoveryWrap — two actions
// routed by the dispatcher. Paired with recovery_session.go (open/close).
//
// The recoverySessionUseError helper is also referenced by group_dek.go's
// HandleDEKRewrapWithOldKey — they share automatically within the same
// (handlers) package.
//
// HandleWrapActivePrivateKey (RK24 reissue) lives in wrap_active_private_key.go.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleRecoverySign signs challenge_token with the old Keeper private key
// during the recovery flow.
//
// Instead of a PEM, takes a `recovery_handle` and signs directly over the
// PEM bytes inside memguard via `RecoverySessionStore.Use`. The PEM is never
// carried in the IPC payload and does not reside in the Extension JS heap.
//
// The signature field is the server's signature over challenge_token. The
// Keeper verifies it with the server public key to confirm challenge_token's
// origin (prevents replay/spoof).
func HandleRecoverySign(d Deps, req proto.RecoverySignRequest) proto.BaseResponse {
	d.Logger.Println("recovery sign request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "recovery sign"); !ok {
		return resp
	}

	var challengeSignatureBase64 string
	useErr := d.RecoverySessions.Use(req.RecoveryHandle, func(rawPEM []byte) error {
		// rawPEM is the LockedBuffer.Bytes() slice owned by the store. While
		// Use holds the mutex, ParsePrivateKey + signing run.
		privKey, err := crypto.ParsePrivateKey(string(rawPEM))
		if err != nil {
			return errors.New("failed to parse private key: " + err.Error())
		}
		sigBytes, err := crypto.SignData(privKey, req.ChallengeToken)
		if err != nil {
			return errors.New("failed to sign challenge token: " + err.Error())
		}
		challengeSignatureBase64 = base64.StdEncoding.EncodeToString(sigBytes)
		return nil
	})
	if useErr != nil {
		return recoverySessionUseError(useErr, "recovery sign")
	}

	d.Logger.Println("recovery sign successful (handle-based)")
	return proto.BaseResponse{Success: true, Data: proto.RecoverySignResponseData{Signature: challengeSignatureBase64}}
}

// recoverySessionUseError delegates to the single sessionUseError helper.
// Backward-compat wrapper for caller compatibility — can be removed gradually.
func recoverySessionUseError(err error, context string) proto.BaseResponse {
	return sessionUseError(err, context)
}

// HandleGenerateKeypairWithRecoveryWrap generates a new RSA keypair and
// immediately wraps the private key with the supplied wrap_key (AES-GCM 32B).
// The new keypair is saved as active in the Keychain.
//
// The private key plaintext never leaves the Keeper. The Extension only
// receives the wrapped result.
//
// The signature field is the server's signature over challenge_token. The
// Keeper verifies it with the server public key.
func HandleGenerateKeypairWithRecoveryWrap(d Deps, req proto.GenerateKeypairWithRecoveryWrapRequest) proto.BaseResponse {
	d.Logger.Println("generate keypair with recovery wrap request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// Wraps the 4-step server signature verification into a single helper call.
	if ok, resp := verifyServerSig(d, req.ChallengeToken, req.Signature, req.ServerKeyVersion, "recovery wrap"); !ok {
		return resp
	}

	// decode wrap_key (AES-GCM 32B raw)
	wrapKey, resp, ok := decodeBase64Len(req.WrapKeyB64, 32, "wrap_key")
	if !ok {
		d.Logger.Printf("recovery wrap error: %s", resp.Error)
		return resp
	}
	defer secure.Zeroize(wrapKey)

	// generate new RSA keypair
	keyPair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		d.Logger.Printf("recovery wrap error: keypair generation failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeInternal, "keypair generation failed: "+err.Error())
	}

	// Move the private key PEM into memguard before any other work and zeroize the original string.
	privKeyBuf := memguard.NewBufferFromBytes([]byte(keyPair.PrivateKey))
	secure.WipeString(&keyPair.PrivateKey)
	defer privKeyBuf.Destroy()

	// wrap private key with AES-GCM
	wrappedB64, err := crypto.AESGCMEncryptBase64(wrapKey, privKeyBuf.Bytes())
	if err != nil {
		d.Logger.Printf("recovery wrap error: AES-GCM wrap failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "AES-GCM wrap failed: "+err.Error())
	}

	// save the new keypair as active in the Keychain
	if err := keychain.SavePrivateKey(d.Store, string(privKeyBuf.Bytes())); err != nil {
		d.Logger.Printf("recovery wrap error: private key save failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "private key save failed: "+err.Error())
	}
	if err := keychain.SavePublicKey(d.Store, keyPair.PublicKey); err != nil {
		d.Logger.Printf("recovery wrap error: public key save failed: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "public key save failed: "+err.Error())
	}

	// delete stale session code from the old identity
	if err := keychain.DeleteSessionCode(d.Store); err != nil {
		d.Logger.Printf("warning: failed to delete existing session code: %v", err)
	}
	// clean up orphaned pending keypair
	_ = keychain.DeletePendingPrivateKey(d.Store)
	_ = keychain.DeletePendingPublicKey(d.Store)

	d.Logger.Println("recovery keypair generated, wrapped, and saved")
	return proto.BaseResponse{Success: true, Data: proto.GenerateKeypairWithRecoveryWrapResponseData{
		PublicKey:     keyPair.PublicKey,
		WrappedKeeper: wrappedB64,
	}}
}
