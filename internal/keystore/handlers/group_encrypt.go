// group_encrypt.go — raw Group DEK direct AES-GCM encrypt handler.
//
// HandleGroupEncrypt is the encrypt-direction mirror of
// HandleGroupDecryptToClipboard (clipboard_actions.go): it seals plaintext
// directly under the raw Group DEK behind the opaque handle, with no Item DEK
// indirection (unlike HandleAESUnwrapAndEncrypt in item_dek.go). The plaintext
// is decoded, sealed inside GroupSessions.Use, and zeroized; the response
// carries only {iv_b64, ciphertext_b64}. Plaintext / raw Group DEK appear zero
// times in the response and logs.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGroupEncrypt AES-GCM-seals the plaintext directly with the raw Group
// DEK behind the opaque handle and returns IV / ciphertext separately.
func HandleGroupEncrypt(d Deps, req proto.GroupEncryptRequest) proto.BaseResponse {
	d.Logger.Println("group encrypt request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64: "+err.Error())
	}
	defer secure.Zeroize(plaintext)

	var iv, ciphertext []byte
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		i, c, err := aesGCMSealSplit(groupDEK, plaintext)
		if err != nil {
			return errors.New("encrypt failed: " + err.Error())
		}
		iv = i
		ciphertext = c
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group encrypt")
	}

	d.Logger.Println("group encrypt successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}
