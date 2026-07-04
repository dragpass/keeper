// meta_decrypt.go — bulk meta-fields decrypt helper.
//
// Consolidates the pattern in `decrypt_meta.go` (2 handlers) and `item_dek.go`
// (`HandleAESUnshareRewrapMeta`) that iterated a meta-fields map and unwrapped
// `Base64(IV(12)||ct)` ciphertexts into a single helper.
//
// Old pattern (3 call sites):
//
//	for key, val := range req.MetaFields {
//	    if val == "" { continue }
//	    raw, err := base64.StdEncoding.DecodeString(val)
//	    // ... or proto.SplitMetaCipherInline(val)
//	    if err != nil { return errors.New("meta "+key+": "+err.Error()) }
//	    if len(raw) < 12 { return errors.New("meta "+key+" too short") }
//	    pt, err := aesGCMOpen(key, raw[:12], raw[12:])
//	    if err != nil { return errors.New("decrypt meta "+key+": "+err.Error()) }
//	    // ... store result + wipe if needed
//	}
//
// New pattern:
//
//	err := decryptMetaFields(key, req.MetaFields, func(name string, pt []byte) error {
//	    // ... store result (caller's responsibility). Empty strings are auto-skipped.
//	    return nil
//	})
//
// The callback fn receives the plaintext bytes — the caller chooses the wipe
// timing (immediate after string conversion, or deferred after a subsequent
// re-encryption step).

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// decryptMetaFields decrypts each entry of metaFields with the given AES-GCM
// key and passes plaintext bytes to the callback. Empty values (`""`) are
// auto-skipped — the caller does not branch on them.
//
// SplitMetaCipherInline does base64 decode + 12B length check + iv/ct split
// in one step. Split / decrypt error messages include the meta name as a
// prefix, so callers can identify which field failed.
//
// Callback errors propagate as-is — the caller retains the existing response
// classification logic (ErrCodeValidation / ErrCodeCryptoFailure /
// ErrCodeInternal) outside the helper.
func decryptMetaFields(
	key []byte,
	metaFields map[string]string,
	fn func(name string, plaintext []byte) error,
) error {
	for name, val := range metaFields {
		if val == "" {
			continue
		}
		iv, ct, splitErr := proto.SplitMetaCipherInline(val)
		if splitErr != nil {
			return errors.New("meta " + name + ": " + splitErr.Error())
		}
		pt, openErr := aesGCMOpen(key, iv, ct)
		if openErr != nil {
			return errors.New("decrypt meta " + name + ": " + openErr.Error())
		}
		if err := fn(name, pt); err != nil {
			return err
		}
	}
	return nil
}
