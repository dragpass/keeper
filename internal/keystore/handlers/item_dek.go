// item_dek.go — Item DEK handlers (AES-GCM family with opaque GroupHandle).
//
// HandleAESGenerateAndWrap / HandleAESUnwrapAndEncrypt.
//
// The UNSHARE_REENCRYPT composite action (HandleAESUnshareRewrapMeta) is a
// 100+ line, 6-step flow in a single function, split out to
// `item_dek_unshare_rewrap.go`.
//
// The old plaintext-returning handler (`HandleAESUnwrapAndDecrypt`) was
// removed. HandleAESRewrap (cross-group Item DEK rewrap) was removed
// alongside the item_dek_grants schema. Shared crypto utils (decodeGroupDEK
// / unwrapItemDEK / aesGCMSeal / aesGCMSealSplit / aesGCMOpen) live in
// `aes_crypto.go`.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAESGenerateAndWrap generates a new 32B Item DEK and returns both the
// raw and the AES-GCM-wrapped (with the Group DEK) result.
func HandleAESGenerateAndWrap(d Deps, req proto.AESGenerateAndWrapRequest) proto.BaseResponse {
	d.Logger.Println("aes generate and wrap request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	// generate Item DEK; raw is zeroized inside the Use callback.
	itemDEK := make([]byte, 32)
	if err := d.FillRandom(itemDEK); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "failed to generate item dek: "+err.Error())
	}
	defer secure.Zeroize(itemDEK)

	var wrapped string
	err := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		var inner error
		wrapped, inner = aesGCMSeal(groupDEK, itemDEK)
		return inner
	})
	if err != nil {
		return groupSessionUseError(err, "wrap item dek")
	}

	d.Logger.Println("aes generate and wrap successful")
	return proto.BaseResponse{Success: true, Data: proto.AESGenerateAndWrapResponseData{
		ItemDEKRawB64:  base64.StdEncoding.EncodeToString(itemDEK),
		WrappedItemDEK: wrapped,
	}}
}

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
		return groupSessionUseError(useErr, "unwrap and encrypt")
	}

	d.Logger.Println("aes unwrap and encrypt successful")
	return proto.BaseResponse{Success: true, Data: proto.AESUnwrapAndEncryptResponseData{
		IVB64:         base64.StdEncoding.EncodeToString(iv),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}}
}

// HandleAESUnwrapAndDecrypt was removed. Available replacement actions:
//   - aes_unwrap_and_decrypt_to_clipboard: writes plaintext directly to the Keeper-owned OS clipboard
//   - aes_unwrap_and_decrypt_meta: bulk-decrypts meta fields (UI-display carve-out)

// HandleAESRewrap (cross-group Item DEK rewrap) was removed alongside the
// item_dek_grants schema. Metadata-only DragLink does not carry a wrapped
// Item DEK; cross-group share is not possible at the server layer.

// The UNSHARE_REENCRYPT composite action (HandleAESUnshareRewrapMeta) lives
// in item_dek_unshare_rewrap.go.
//
// Shared crypto utils (DecodeGroupDEK / UnwrapItemDEK / AESGCMSeal /
// AESGCMSealSplit / AESGCMOpen + lowercase aliases) were split into
// `aes_crypto.go`.
