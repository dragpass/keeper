// group_encrypt_aad.go — raw Group DEK direct AES-GCM encrypt handler with AAD
// binding.
//
// HandleGroupEncryptWithAAD is the AAD-binding variant of HandleGroupEncrypt
// (group_encrypt.go): it seals plaintext directly under the raw Group DEK behind
// the opaque handle, additionally binding a caller-supplied AAD into the GCM tag
// so the ciphertext is tied to its canonical context and cannot be swapped. The
// plaintext is decoded, sealed inside GroupSessions.Use, and zeroized; the
// response carries only {iv_b64, ciphertext_b64}. Plaintext / raw Group DEK
// appear zero times in the response and logs. The AAD is public context material.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGroupEncryptWithAAD AES-GCM-seals the plaintext directly with the raw
// Group DEK behind the opaque handle, binding the AAD into the tag, and returns
// IV / ciphertext separately.
func HandleGroupEncryptWithAAD(d Deps, req proto.GroupEncryptWithAADRequest) proto.BaseResponse {
	d.Logger.Println("group encrypt with aad request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode plaintext_b64: "+err.Error())
	}
	defer secure.Zeroize(plaintext)

	// AAD is public context material, not secret; no zeroize needed. Validate()
	// already confirmed it is non-empty valid Base64.
	aad, err := base64.StdEncoding.DecodeString(req.AADB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to decode aad_b64: "+err.Error())
	}

	var iv, ciphertext []byte
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		i, c, err := aesGCMSealSplitWithAAD(groupDEK, plaintext, aad)
		if err != nil {
			return errors.New("encrypt failed: " + err.Error())
		}
		iv = i
		ciphertext = c
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group encrypt with aad")
	}

	d.Logger.Println("group encrypt with aad successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}
