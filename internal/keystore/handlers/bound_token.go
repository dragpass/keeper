// bound_token.go — the bound drag-token actions.
//
// Each action checks, in order, before any plaintext is produced:
//
//	structural validation (token_expiry is `never` or a canonical epoch;
//	  an empty value is not "no expiry")
//	  → the token has not expired at the Keeper's clock (no grace)
//	  → personal: this device has a signed-in account binding, whose account
//	    id goes into the AAD
//	  → Group: the handle is not audit-only, and a labeled handle names the
//	    same org, group and version as the request
//	  → the open succeeds under the AAD built here (proto/bound_token.go)
//
// Expiry is checked before the key is touched so an expired token never
// reaches the clipboard; the tag then proves the expiry the caller named is
// the one the token was sealed with. See docs/protocol.md "Bound drag tokens".

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
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

var errBoundScopeMismatch = errors.New("group handle scope does not match the bound token")

func tokenFailure(code, message string) proto.BaseResponse {
	return errs.CodeResponse(errs.ErrorCode(code), message)
}

// legacyTokenRefused answers every AAD-free drag action. Their tokens carry
// an expiry nobody can authenticate, so the Keeper neither seals nor opens
// them (docs/protocol.md "Bound drag tokens").
func legacyTokenRefused(d Deps, action string) proto.BaseResponse {
	d.Logger.Println(action + " refused: legacy drag token format")
	return tokenFailure(proto.TokenLegacyRefused,
		"this drag token format has no authenticated expiry; use the bound token actions")
}

// boundExpiry parses an already validated token_expiry and refuses it once
// it has passed.
func boundExpiry(d Deps, value, action string) (proto.TokenExpiry, proto.BaseResponse, bool) {
	expiry, err := proto.ParseTokenExpiry(value)
	if err != nil {
		return proto.TokenExpiry{}, tokenFailure(proto.TokenInvalidInput, err.Error()), false
	}
	if expiry.ExpiredAt(d.Now().Unix()) {
		d.Logger.Println(action + " refused: token expired")
		return proto.TokenExpiry{}, tokenFailure(proto.TokenExpired, "the drag token has expired"), false
	}
	return expiry, proto.BaseResponse{}, true
}

// boundAccountID is the signed-in account of this device. It is a binding
// any Native Messaging caller can rewrite, so it is not authentication; it
// only names the scope, and a wrong account fails the tag.
func boundAccountID(d Deps, action string) (string, proto.BaseResponse, bool) {
	binding, present, err := keychain.GetAccountBinding(d.Store)
	if err != nil {
		d.Logger.Printf("%s: account binding unreadable: %s", action, deviceIdentityErrorClass(err))
		return "", deviceIdentityErrorResponse(err), false
	}
	if !present || binding.SignedOut || binding.AccountID == "" {
		d.Logger.Println(action + " refused: no signed-in account binding on this device")
		return "", tokenFailure(proto.TokenAccountUnbound, "this device has no signed-in account for a personal token"), false
	}
	return binding.AccountID, proto.BaseResponse{}, true
}

// withPersonalDEK unwraps the device-wrapped personal DEK for fn and
// zeroizes it afterwards.
func withPersonalDEK(d Deps, supplied string, fn func(dek []byte) proto.BaseResponse) proto.BaseResponse {
	encryptedDEK, _, resp, ok := deviceWrappedDEK(d, supplied)
	if !ok {
		return resp
	}
	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()
	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), encryptedDEK)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	defer secure.Zeroize(dek)
	return fn(dek)
}

func sealedResponse(iv, ciphertext []byte) proto.BaseResponse {
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}

// HandleDEKUnwrapAndEncryptBound seals a personal bound token.
func HandleDEKUnwrapAndEncryptBound(d Deps, req proto.DEKUnwrapAndEncryptBoundRequest) proto.BaseResponse {
	const action = "dek unwrap and encrypt bound"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	expiry, resp, ok := boundExpiry(d, req.TokenExpiry, action)
	if !ok {
		return resp
	}
	accountID, resp, ok := boundAccountID(d, action)
	if !ok {
		return resp
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64")
	}
	defer secure.Zeroize(plaintext)
	aad := []byte(proto.BoundPersonalTokenAAD(accountID, expiry))
	return withPersonalDEK(d, req.EncryptedDEKB64, func(dek []byte) proto.BaseResponse {
		iv, ciphertext, err := crypto.SealAESGCM(d.Random(), dek, plaintext, aad)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeCryptoFailure, "encrypt failed")
		}
		d.Logger.Println(action + " successful")
		return proto.BaseResponse{Success: true, Data: proto.DEKUnwrapAndEncryptResponseData{
			IVB64:         base64.StdEncoding.EncodeToString(iv),
			CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		}}
	})
}

// HandleDEKUnwrapAndDecryptBoundToClipboard opens a personal bound token into
// the OS clipboard. The response carries no plaintext.
func HandleDEKUnwrapAndDecryptBoundToClipboard(d Deps, req proto.DEKUnwrapAndDecryptBoundToClipboardRequest) proto.BaseResponse {
	const action = "dek unwrap and decrypt bound to clipboard"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	expiry, resp, ok := boundExpiry(d, req.TokenExpiry, action)
	if !ok {
		return resp
	}
	accountID, resp, ok := boundAccountID(d, action)
	if !ok {
		return resp
	}
	iv, _ := base64.StdEncoding.DecodeString(req.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(req.CiphertextB64)
	aad := []byte(proto.BoundPersonalTokenAAD(accountID, expiry))
	return withPersonalDEK(d, req.EncryptedDEKB64, func(dek []byte) proto.BaseResponse {
		plaintext, err := crypto.OpenAESGCM(dek, iv, ciphertext, aad)
		if err != nil {
			d.Logger.Println(action + " failed (gcm)")
			return tokenFailure(proto.TokenDecryptFailed, "bound token decrypt failed")
		}
		return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, action)
	})
}

// checkBoundLabel holds a labeled handle to the scope the request names. An
// unlabeled handle (a legacy-policy grant) remembers no scope; the AAD alone
// binds it.
func checkBoundLabel(label sessions.Label, tc proto.GroupBoundTokenContext) error {
	if isAuditOnlyLabel(label) {
		return errHandleAuditOnly
	}
	if label.GroupID == "" && label.DekVersion == 0 {
		if label.OrgID != "" && label.OrgID != tc.OrgID {
			return errBoundScopeMismatch
		}
		return nil
	}
	if label.OrgID != tc.OrgID || label.GroupID != tc.GroupID || label.DekVersion != tc.DekVersion {
		return errBoundScopeMismatch
	}
	return nil
}

func boundSessionError(err error, action string) proto.BaseResponse {
	if errors.Is(err, errBoundScopeMismatch) {
		return tokenFailure(proto.TokenScopeMismatch,
			"the group handle was opened for another org, group or version")
	}
	return handleSessionError(err, action)
}

// HandleGroupEncryptBound seals a Group bound token under the raw Group DEK
// behind the handle.
func HandleGroupEncryptBound(d Deps, req proto.GroupEncryptBoundRequest) proto.BaseResponse {
	const action = "group encrypt bound"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	tc := req.TokenContext()
	expiry, resp, ok := boundExpiry(d, tc.TokenExpiry, action)
	if !ok {
		return resp
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64")
	}
	defer secure.Zeroize(plaintext)
	aad := []byte(proto.BoundGroupTokenAAD(tc.OrgID, tc.GroupID, tc.DekVersion, tc.AuditTableID, expiry))

	var iv, ciphertext []byte
	useErr := d.GroupSessions.UseLabeled(tc.GroupHandle, func(groupDEK []byte, label sessions.Label) error {
		if err := checkBoundLabel(label, tc); err != nil {
			return err
		}
		if isDecryptOnlyLabel(label) {
			return errHandleDecryptOnly
		}
		i, c, err := crypto.SealAESGCM(d.Random(), groupDEK, plaintext, aad)
		if err != nil {
			return errors.New("encrypt failed")
		}
		iv, ciphertext = i, c
		return nil
	})
	if useErr != nil {
		return boundSessionError(useErr, action)
	}
	d.Logger.Println(action + " successful")
	return sealedResponse(iv, ciphertext)
}

// HandleGroupDecryptBoundToClipboard opens a Group bound token into the OS
// clipboard. The response carries no plaintext.
func HandleGroupDecryptBoundToClipboard(d Deps, req proto.GroupDecryptBoundToClipboardRequest) proto.BaseResponse {
	const action = "group decrypt bound to clipboard"
	d.Logger.Println(action + " request processing...")
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	tc := req.TokenContext()
	expiry, resp, ok := boundExpiry(d, tc.TokenExpiry, action)
	if !ok {
		return resp
	}
	iv, _ := base64.StdEncoding.DecodeString(req.IVB64)
	ciphertext, _ := base64.StdEncoding.DecodeString(req.CiphertextB64)
	aad := []byte(proto.BoundGroupTokenAAD(tc.OrgID, tc.GroupID, tc.DekVersion, tc.AuditTableID, expiry))

	var plaintext []byte
	var openErr error
	useErr := d.GroupSessions.UseLabeled(tc.GroupHandle, func(groupDEK []byte, label sessions.Label) error {
		if err := checkBoundLabel(label, tc); err != nil {
			return err
		}
		plaintext, openErr = crypto.OpenAESGCM(groupDEK, iv, ciphertext, aad)
		return nil
	})
	if useErr != nil {
		return boundSessionError(useErr, action)
	}
	if openErr != nil {
		d.Logger.Println(action + " failed (gcm)")
		return tokenFailure(proto.TokenDecryptFailed, "bound token decrypt failed")
	}
	return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, action)
}
