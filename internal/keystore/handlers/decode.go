// Base64 helpers never include input values in error messages.

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
