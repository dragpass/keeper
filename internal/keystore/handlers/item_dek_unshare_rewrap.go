// item_dek_unshare_rewrap.go — UNSHARE_REENCRYPT composite action.
//
// Separated from `item_dek.go`'s simple wrap/encrypt/rewrap handlers. The
// handler in this file is a 6-step composite flow — "revoke existing grants
// + re-encrypt value/meta + issue new grants" — that exceeds 100 lines in a
// single function, so it gets its own file.

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleAESUnshareRewrapMeta is the UNSHARE_REENCRYPT composite action.
//
// Flow (all inside Keeper memory):
//  1. unwrap OLD wrapped_item_dek with src group_handle → OLD Item DEK
//  2. decrypt value plaintext with OLD Item DEK + iv/ct → hold plaintext
//  3. decrypt each meta_fields entry with OLD Item DEK → hold meta plaintext
//  4. generate new 32B Item DEK (d.Rand / crypto/rand default)
//  5. re-encrypt value + re-encrypt meta with the new Item DEK
//  6. wrap the new Item DEK for each of src group_handle + extra_dst_group_handles[]
//
// Response: {new_encrypted_value, new_encrypted_fields, new_grants[]}.
// Plaintext / Item DEK / meta plaintext are never echoed to the response envelope.
func HandleAESUnshareRewrapMeta(d Deps, req proto.AESUnshareRewrapMetaRequest) proto.BaseResponse {
	d.Logger.Println("aes unshare rewrap meta request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	iv, resp, ok := decodeBase64Len(req.IVB64, 12, "iv_b64")
	if !ok {
		return resp
	}
	ciphertext, resp, ok := decodeBase64(req.CiphertextB64, "ciphertext_b64")
	if !ok {
		return resp
	}

	// 1) OLD Item DEK unwrap + value/meta decrypt — all done inside the src group session
	var plaintext []byte
	plaintextFields := map[string][]byte{}
	useSrcErr := d.GroupSessions.Use(req.SrcGroupHandle, func(srcGroupDEK []byte) error {
		oldItemDEK, err := unwrapItemDEK(srcGroupDEK, req.WrappedItemDEK)
		if err != nil {
			return err
		}
		defer secure.Zeroize(oldItemDEK)

		pt, err := aesGCMOpen(oldItemDEK, iv, ciphertext)
		if err != nil {
			return errors.New("value decrypt failed: " + err.Error())
		}
		plaintext = pt

		return decryptMetaFields(oldItemDEK, req.MetaFields, func(name string, pt []byte) error {
			plaintextFields[name] = pt
			return nil
		})
	})
	if useSrcErr != nil {
		return groupSessionUseError(useSrcErr, "unshare rewrap meta src")
	}
	defer secure.Zeroize(plaintext)
	defer func() {
		for _, b := range plaintextFields {
			secure.Zeroize(b)
		}
	}()

	// 2) generate new 32B Item DEK
	newItemDEK := make([]byte, 32)
	if err := d.FillRandom(newItemDEK); err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "rand newItemDEK: "+err.Error())
	}
	defer secure.Zeroize(newItemDEK)

	// 3) re-encrypt value + re-encrypt meta with the new Item DEK
	newValueWrap, err := aesGCMSeal(newItemDEK, plaintext)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeInternal, "value reseal: "+err.Error())
	}
	newEncryptedFields := map[string]string{}
	for key, pt := range plaintextFields {
		w, err := aesGCMSeal(newItemDEK, pt)
		if err != nil {
			return errs.CodeResponse(errs.ErrCodeInternal, "meta reseal "+key+": "+err.Error())
		}
		newEncryptedFields[key] = w
	}

	// 4) wrap the new Item DEK for src + each extra dst group
	grants := make([]proto.AESUnshareRewrapMetaGrant, 0, 1+len(req.ExtraDstGroupHandles))
	allHandles := append([]string{req.SrcGroupHandle}, req.ExtraDstGroupHandles...)
	for _, handle := range allHandles {
		var wrapped string
		useDstErr := d.GroupSessions.Use(handle, func(dstGroupDEK []byte) error {
			w, err := aesGCMSeal(dstGroupDEK, newItemDEK)
			if err != nil {
				return errors.New("dst wrap " + handle + ": " + err.Error())
			}
			wrapped = w
			return nil
		})
		if useDstErr != nil {
			return groupSessionUseError(useDstErr, "unshare rewrap meta dst "+handle)
		}
		grants = append(grants, proto.AESUnshareRewrapMetaGrant{
			GroupHandle:    handle,
			WrappedItemDEK: wrapped,
		})
	}

	d.Logger.Println("aes unshare rewrap meta successful")
	return proto.BaseResponse{Success: true, Data: proto.AESUnshareRewrapMetaResponseData{
		NewEncryptedValue:  newValueWrap,
		NewEncryptedFields: newEncryptedFields,
		NewGrants:          grants,
	}}
}
