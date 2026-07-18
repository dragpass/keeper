// Package errs — Error Taxonomy.
//
// **Goal:** The `error` field in a Native Messaging response was previously
// just a human-readable message — there was no stable token the Extension
// could use for branching / UX handling. This layer introduces a **coarse**
// `ErrorCode` so that the Extension can distinguish (a) messages shown to
// the user from (b) code-level handling such as automatic retry / cache
// invalidation.
//
// **Design principles:**
//
//  1. **Block sensitive-value echo** — codes are short enum-like strings only.
//     The message (`Error` field) is used as the handler-sanitized result.
//  2. **Preserve existing compat** — the `ErrorCode` field is optional
//     (omitempty). Older Extensions can ignore it and still function.
//  3. **Sentinel error mapping** — instead of defining new error types, decide
//     the code by checking existing sentinels (`ErrSecretNotFound`,
//     `ErrRecoverySessionExpired`, etc.) via `errors.Is`. Adopted gradually.
//  4. **Functional categorization**, **not** security categorization — codes
//     like `not_found` / `expired_session` describe "how the Extension should
//     react", not "what information an attacker can learn."
//
// **Gradual adoption:** the code enum + mapper + helpers are defined and a
// few worked examples have been migrated. The package lives outside keystore
// root as its own subpackage.
//
// **Naming choice:** the package name is `errs` — intentionally
// shortened to avoid shadowing the stdlib `errors` package (`errors.Is` must
// remain callable). To also avoid stuttering at the call site
// (`errs.ErrorResponse`), function names were shortened to `Response` /
// `CodeResponse`. `errs_aliases.go` in keystore root preserves backward
// compatibility via var aliases (`errorResponse=errs.Response`,
// `errorCodeResponse=errs.CodeResponse`).
package errs

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/sessions"
)

// ErrorCode is the coarse category token placed in the `error_code` field
// of a Native Messaging response. The Extension branches only on this value
// and uses the message for user-facing copy or diagnostic logs.
type ErrorCode string

// 7 codes. Defined in keeper-open-source-quality-plan.md per the P2 plan.
const (
	// ErrCodeValidation: payload format / length / required-field validation
	// failed. Extension-side bug or a call to an incompatible action. Retry
	// is pointless.
	ErrCodeValidation ErrorCode = "validation_error"

	// ErrCodeNotFound: the requested resource (secret slot, session handle,
	// server key version) does not exist. The Extension typically tries
	// bootstrapping / re-login.
	ErrCodeNotFound ErrorCode = "not_found"

	// ErrCodeExpiredSession: the handle's TTL has expired. The Extension
	// should call store.Open again to obtain a fresh handle and then retry.
	ErrCodeExpiredSession ErrorCode = "expired_session"

	// ErrCodeCryptoFailure: AES-GCM decrypt failure, RSA-OAEP failure, or
	// signature verification failure. Wrong wrap_key / user key, or tampered
	// payload. Retry is pointless.
	ErrCodeCryptoFailure ErrorCode = "crypto_failure"

	// ErrCodeStorageFailure: OS Keychain access denied, file permission,
	// or other storage I/O level errors. The Extension prompts the user
	// about permissions.
	ErrCodeStorageFailure ErrorCode = "storage_failure"

	// ErrCodeUnsupported: unsupported action or protocol version. The
	// Extension prompts the user to upgrade Keeper.
	ErrCodeUnsupported ErrorCode = "unsupported"

	// ErrCodeInternal: an unexpected error that does not fall into the above
	// categories. If reproducible, target for a bug report.
	ErrCodeInternal ErrorCode = "internal_error"
)

// CodeForError inspects an error and returns the matching coarse code.
// Unknown errors map to ErrCodeInternal. nil → "" (callers on the success
// branch should not call this).
//
// Mapping policy:
//
//   - *proto.ValidationError              → ErrCodeValidation
//   - keychain.ErrSecretNotFound /
//     keychain.ErrServerKeyVersionNotFound /
//     keychain.ErrNoActiveServerKey /
//     sessions.ErrRecoverySessionNotFound /
//     sessions.ErrGroupSessionNotFound    → ErrCodeNotFound
//   - sessions.ErrRecoverySessionExpired /
//     sessions.ErrGroupSessionExpired     → ErrCodeExpiredSession
//   - all others                           → ErrCodeInternal
//
// crypto_failure / storage_failure / unsupported are assigned by the caller
// directly via CodeResponse(ErrCodeCryptoFailure, ...) at stages where few
// explicit sentinels are categorized.
func CodeForError(err error) ErrorCode {
	if err == nil {
		return ""
	}
	if proto.IsValidationError(err) {
		return ErrCodeValidation
	}
	switch {
	case errors.Is(err, keychain.ErrSecretNotFound),
		errors.Is(err, keychain.ErrServerKeyVersionNotFound),
		errors.Is(err, keychain.ErrNoActiveServerKey),
		errors.Is(err, sessions.ErrRecoverySessionNotFound),
		errors.Is(err, sessions.ErrRecoveryKeySessionNotFound),
		errors.Is(err, sessions.ErrGroupSessionNotFound):
		return ErrCodeNotFound
	case errors.Is(err, sessions.ErrRecoverySessionExpired),
		errors.Is(err, sessions.ErrRecoveryKeySessionExpired),
		errors.Is(err, sessions.ErrGroupSessionExpired):
		return ErrCodeExpiredSession
	}
	return ErrCodeInternal
}

// Response shapes err into a Native Messaging response envelope. If err is
// nil it returns success=false with an empty message (defensive guard —
// callers should not pass nil).
//
// The message (`Error` field) uses err.Error() verbatim — handlers are
// responsible for sanitizing. The code uses CodeForError mapping.
//
// Named simply `Response` to avoid package stuttering
// (`errs.ErrorResponse`). The keystore root `errorResponse` alias preserves
// compatibility with existing callers.
func Response(err error) proto.BaseResponse {
	if err == nil {
		return proto.BaseResponse{Success: false}
	}
	return proto.BaseResponse{
		Success:   false,
		Error:     err.Error(),
		ErrorCode: string(CodeForError(err)),
	}
}

// CodeResponse is used when the caller wants to assign an explicit code.
// Use it when a handler categorizes errors directly for categories that
// CodeForError cannot auto-map (crypto_failure, storage_failure, unsupported).
//
// Named simply `CodeResponse` to avoid package stuttering
// (`errs.ErrorCodeResponse`). The keystore root `errorCodeResponse` alias
// preserves compatibility with existing callers.
func CodeResponse(code ErrorCode, message string) proto.BaseResponse {
	return proto.BaseResponse{
		Success:   false,
		Error:     message,
		ErrorCode: string(code),
	}
}
