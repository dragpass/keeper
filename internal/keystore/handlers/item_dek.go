// Item DEK handlers operate through opaque Group DEK handles.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAESUnwrapAndEncrypt unwraps the Item DEK with the Group DEK,
// AES-GCM-encrypts the plaintext, and returns IV / ciphertext separately.
func HandleAESUnwrapAndEncrypt(d Deps, req proto.AESUnwrapAndEncryptRequest) proto.BaseResponse {
	d.Logger.Println("aes unwrap and encrypt request processing...")

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
		itemDEK, err := unwrapItemDEK(groupDEK, req.WrappedItemDEK)
		if err != nil {
			return err
		}
		defer secure.Zeroize(itemDEK)

		i, c, err := aesGCMSealSplit(itemDEK, plaintext)
		if err != nil {
			return errors.New("encrypt failed: " + err.Error())
		}
		iv = i
		ciphertext = c
		return nil
	})
	if useErr != nil {
		return sessionUseError(useErr, "unwrap and encrypt")
	}

	d.Logger.Println("aes unwrap and encrypt successful")
	return proto.BaseResponse{Success: true, Data: proto.AESUnwrapAndEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}
