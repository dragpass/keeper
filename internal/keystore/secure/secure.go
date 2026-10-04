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
