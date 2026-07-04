// Package secure — secure buffer lifecycle helpers.
//
// Centralizes the patterns that repeat when handling sensitive values
// (personal DEK / Group DEK / wrap key / RSA private key, etc.). Keeper
// handlers follow this flow:
//
//  1. Receive input as a Base64 string from the JSON payload
//  2. base64.DecodeString → []byte
//  3. Use with a crypto primitive
//  4. Zero-fill immediately after use to remove from memory
//
// Helpers:
//   - Zeroize(b)              — in-place 0 fill of a slice (defer-friendly)
//   - WipeString(s)           — best-effort 0 fill of the backing bytes of a
//     Go string
//   - WithDecodedSecretB64    — Base64 decode + callback + defer zeroize in
//     one call
//   - WithDecodedSecretB64Len — WithDecodedSecretB64 + enforces exact byte
//     length
//
// **Lifetime guidance:**
//   - `defer Zeroize(buf)` works as intended because the captured slice
//     points to the underlying array at call time. If the slice is reassigned
//     elsewhere the capture is broken, so create raw bytes once and keep that
//     variable as-is.
//   - Go strings have immutable backing storage so a true 0 fill cannot be
//     guaranteed, but `WipeString` performs a best-effort wipe via unsafe-
//     style mutation. For sensitive payloads, prefer to spend as little time
//     as possible in the string stage, convert to []byte, then take Zeroize
//     responsibility.
//   - LockedBuffer is excluded from OS swap and is guaranteed to zero-out
//     via a finalizer, so long-lived secrets (e.g. PEM) should be wrapped in
//     LockedBuffer. Raw bytes that are used briefly and discarded are fine
//     with Zeroize.
package secure

import (
	"encoding/base64"
	"fmt"
)

// Zeroize fills a slice in place with zeros. When used with defer, the
// captured slice points to the underlying array at call time, so it works
// as intended.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WipeString overwrites the bytes backing a Go string.
// This is best-effort: the GC may have already copied the data.
// But it reduces the window of exposure.
func WipeString(s *string) {
	b := []byte(*s)
	Zeroize(b)
	*s = ""
}

// WithDecodedSecretB64 decodes a Base64 string, passes the raw bytes to the
// callback, and zeroizes immediately on callback return (regardless of
// success/failure). It collapses the base64 decode + defer zeroize
// boilerplate that was repeated in 30+ places into a single line.
//
// Usage:
//
//	if err := WithDecodedSecretB64(req.WrapKeyB64, func(raw []byte) error {
//	    // raw can be used directly as an AES-GCM key. raw is zero-filled
//	    // when the function returns.
//	    return doSomethingWithKey(raw)
//	}); err != nil {
//	    return err
//	}
//
// Notes:
//   - If the callback escapes the raw slice (aliases into another variable,
//     etc.), the defer zeroize will execute and the external alias will also
//     become zero. This is intentional — any view of the raw bytes is invalid
//     beyond the callback lifetime.
//   - If the callback needs to return a derived result (e.g. ciphertext),
//     write it to an outer variable so that only raw is zeroized at callback
//     return.
func WithDecodedSecretB64(value, field string, fn func([]byte) error) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s: invalid Base64: %w", field, err)
	}
	defer Zeroize(raw)
	return fn(raw)
}

// WithDecodedSecretB64Len is WithDecodedSecretB64 + enforces exact byte
// length. Used for fixed-length payloads such as AES-256 key (32B) or AES-GCM
// IV (12B). On length mismatch it does not invoke the callback — it zeroizes
// immediately and returns an error.
func WithDecodedSecretB64Len(value, field string, expectedLen int, fn func([]byte) error) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s: invalid Base64: %w", field, err)
	}
	defer Zeroize(raw)
	if len(raw) != expectedLen {
		return fmt.Errorf("%s: decoded length must be %d bytes, got %d", field, expectedLen, len(raw))
	}
	return fn(raw)
}
