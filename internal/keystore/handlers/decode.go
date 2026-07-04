// decode.go — Base64 decode + length validation helpers.
//
// proto.Validate() already performs the same validation (`requireBase64`,
// `requireBase64Len`), but handlers need the decoded raw bytes for actual
// processing, so the pattern of repeating decode + length guard per handler
// is consolidated into a single helper.
//
// Old pattern (40+ call sites):
//
//	raw, err := base64.StdEncoding.DecodeString(req.SomeB64)
//	if err != nil {
//	    return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode some: "+err.Error())
//	}
//	if len(raw) != 32 {
//	    return errs.CodeResponse(errs.ErrCodeValidation, "some must be 32 bytes")
//	}
//
// New pattern:
//
//	raw, resp, ok := decodeBase64Len(req.SomeB64, 32, "some_b64")
//	if !ok { return resp }
//
// All length mismatches / decode errors classify as ErrCodeValidation. fieldName
// is included in the response message but the input value is not echoed
// (consistent with the validation sentinel).

package handlers

import (
	"encoding/base64"
	"strconv"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// decodeBase64 decodes a variable-length Base64 field (ciphertext, wrapped_*,
// encrypted_*). The caller performs any additional length validation (e.g.,
// rejecting GCM tags shorter than 16B).
func decodeBase64(b64, fieldName string) ([]byte, proto.BaseResponse, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errs.CodeResponse(
			errs.ErrCodeValidation,
			"failed to decode "+fieldName+": "+err.Error(),
		), false
	}
	return raw, proto.BaseResponse{}, true
}

// decodeBase64Len decodes + validates the length of a Base64 field with a
// fixed expected length (IV 12B / 32B raw DEK, etc.). Used for AES-GCM IV
// (12B) / 32B AES-256 keys / RSA signature lengths. On a length mismatch the
// message only states expectedLen (no input value echo).
func decodeBase64Len(b64 string, expectedLen int, fieldName string) ([]byte, proto.BaseResponse, bool) {
	raw, resp, ok := decodeBase64(b64, fieldName)
	if !ok {
		return nil, resp, false
	}
	if len(raw) != expectedLen {
		return nil, errs.CodeResponse(
			errs.ErrCodeValidation,
			fieldName+" must be "+strconv.Itoa(expectedLen)+" bytes",
		), false
	}
	return raw, proto.BaseResponse{}, true
}
