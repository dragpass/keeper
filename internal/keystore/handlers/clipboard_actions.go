// clipboard_actions.go — decrypt-to-clipboard handlers.
//
// Handlers decrypt plaintext inside Keeper memory and immediately delegate to the
// OS clipboard via d.Clipboard.Write. The response carries no plaintext — it
// only returns {copied, clipboard_ttl_ms}.
//
// See security/keeper-plaintext-command-api-plan.md.

package handlers

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/dragpass/keeper/internal/keystore/clipboard"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleDEKUnwrapAndDecryptToClipboard is the AAD-free personal drag open. Its
// tokens carry no authenticated expiry, so it is refused; use
// dek_unwrap_and_decrypt_bound_to_clipboard (bound_token.go).
func HandleDEKUnwrapAndDecryptToClipboard(d Deps, _ proto.DEKUnwrapAndDecryptToClipboardRequest) proto.BaseResponse {
	return legacyTokenRefused(d, "dek unwrap and decrypt to clipboard")
}

// HandleGroupDecryptToClipboard is the AAD-free Group drag open. Its tokens
// carry no authenticated expiry, so it is refused; use
// group_decrypt_bound_to_clipboard (bound_token.go).
func HandleGroupDecryptToClipboard(d Deps, _ proto.GroupDecryptToClipboardRequest) proto.BaseResponse {
	return legacyTokenRefused(d, "group decrypt to clipboard")
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
// main.go swapped in a MemoryClipboard under KEEPER_E2E_MODE. Only a
// keeper_e2e build registers the action (dispatch/registry_e2e.go).
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
