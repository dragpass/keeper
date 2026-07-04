// clipboard_actions.go — decrypt-to-clipboard handlers.
// HandleAESUnwrapAndDecryptToClipboard / HandleDEKUnwrapAndDecryptToClipboard.
//
// Both handlers take the same input as the existing AES/DEK unwrap+decrypt,
// decrypt the plaintext inside Keeper memory, and immediately delegate to the
// OS clipboard via d.Clipboard.Write. The response carries no plaintext — it
// only returns {copied, clipboard_ttl_ms}.
//
// See security/keeper-plaintext-command-api-plan.md.

package handlers

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAESUnwrapAndDecryptToClipboard writes the group entry plaintext
// directly to the OS clipboard. The response contains no plaintext.
func HandleAESUnwrapAndDecryptToClipboard(d Deps, req proto.AESUnwrapAndDecryptToClipboardRequest) proto.BaseResponse {
	d.Logger.Println("aes unwrap and decrypt to clipboard request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}

	var plaintext []byte
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		itemDEK, err := unwrapItemDEK(groupDEK, req.WrappedItemDEK)
		if err != nil {
			return err
		}
		defer secure.Zeroize(itemDEK)

		pt, err := aesGCMOpen(itemDEK, iv, ciphertext)
		if err != nil {
			return errors.New("decrypt failed: " + err.Error())
		}
		plaintext = pt
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "unwrap and decrypt to clipboard")
	}
	return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, "aes unwrap and decrypt to clipboard")
}

// HandleDEKUnwrapAndDecryptToClipboard writes the personal DEK plaintext
// directly to the OS clipboard. The response contains no plaintext.
func HandleDEKUnwrapAndDecryptToClipboard(d Deps, req proto.DEKUnwrapAndDecryptToClipboardRequest) proto.BaseResponse {
	d.Logger.Println("dek unwrap and decrypt to clipboard request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), req.EncryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	defer secure.Zeroize(dek)

	plaintext, err := aesGCMOpen(dek, iv, ciphertext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, "decrypt failed: "+err.Error())
	}
	return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, "dek unwrap and decrypt to clipboard")
}

// HandleGroupDecryptToClipboard writes the plaintext of a drag / audit token
// (encrypted directly with the raw Group DEK) to the OS clipboard. There is
// no Item DEK indirection (unlike DragLink Item DEK tokens), so aesGCMOpen is
// called directly inside GroupSessions.Use.
//
// Plaintext appears zero times in the response — only {copied, ttl}.
func HandleGroupDecryptToClipboard(d Deps, req proto.GroupDecryptToClipboardRequest) proto.BaseResponse {
	d.Logger.Println("group decrypt to clipboard request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}

	var plaintext []byte
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		pt, err := aesGCMOpen(groupDEK, iv, ciphertext)
		if err != nil {
			return errors.New("decrypt failed: " + err.Error())
		}
		plaintext = pt
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group decrypt to clipboard")
	}
	return finalizeClipboardCopy(d, plaintext, req.ClipboardTTLMs, "group decrypt to clipboard")
}

// writeClipboard consolidates d.Clipboard calls in one place. Defensive guard
// that returns an explicit failure instead of panicking if Clipboard is not
// injected.
func writeClipboard(d Deps, plaintext []byte, ttlMs int64) error {
	cb := d.Clipboard
	if cb == nil {
		return errors.New("clipboard not configured")
	}
	return cb.Write(plaintext, time.Duration(ttlMs)*time.Millisecond)
}

// finalizeClipboardCopy bundles the closing 5-line pattern shared by the 3
// clipboard handlers into a single helper. The helper owns plaintext zeroize,
// so callers just do `return finalizeClipboardCopy(...)` right after decrypt.
//
//   - Zeroize plaintext (defer)
//   - call writeClipboard + return Internal response on failure
//   - log success
//   - build ClipboardCopyResponseData {copied:true, ttl:ttlMs}
//
// logName is the logger-message prefix (the action name). Never echo
// plaintext (sentinel regression-guard alignment).
func finalizeClipboardCopy(d Deps, plaintext []byte, ttlMs int64, logName string) proto.BaseResponse {
	defer secure.Zeroize(plaintext)

	if err := writeClipboard(d, plaintext, ttlMs); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "clipboard write failed: "+err.Error())
	}

	d.Logger.Println(logName + " successful")
	return proto.BaseResponse{Success: true, Data: proto.ClipboardCopyResponseData{
		Copied:         true,
		ClipboardTTLMs: ttlMs,
	}}
}

// HandleClipboardGetLastHash is a test-only action. The Extension `pnpm e2e`
// flow calls it to verify (by SHA-256 hash compare) that the dispatch path
// (background → Keeper → Clipboard.Write) sent the correct plaintext.
//
// The production OSClipboard does not export a hash accessor, so the type
// assertion gates this naturally — it only returns a normal response when
// main.go swapped in a MemoryClipboard under KEEPER_E2E_MODE.
func HandleClipboardGetLastHash(d Deps, _ proto.ClipboardGetLastHashRequest) proto.BaseResponse {
	d.Logger.Println("clipboard get last hash request processing...")

	mc, ok := d.Clipboard.(*clipboard.MemoryClipboard)
	if !ok {
		return errs.CodeResponse(errs.ErrCodeUnsupported, "clipboard_get_last_hash requires MemoryClipboard (KEEPER_E2E_MODE only)")
	}

	hash, has := mc.LastHash()
	return proto.BaseResponse{Success: true, Data: proto.ClipboardGetLastHashResponseData{
		HasHash:     has,
		LastHashB64: base64.StdEncoding.EncodeToString(hash[:]),
		WriteCount:  mc.WriteCount(),
		LastTTLMs:   mc.LastTTLMs(),
	}}
}

// loadDeviceKeyFromKeychain alias — same signature as dek.go's helper. This
// file is in the same package as dek.go, so direct calls work. No separate
// definition needed (compile-time check only).
var _ = keychain.GetDeviceKey // keep keychain import live for clarity
