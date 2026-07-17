// group_meta.go — raw Group DEK direct batch metadata encrypt/decrypt handlers.
//
// Metadata-path counterparts of HandleGroupEncrypt: the Item DEK unwrap step
// of HandleAESUnwrapAndDecryptMeta is replaced by a direct AES-GCM run against
// the raw Group DEK behind the opaque handle (GroupSessions.Use), with no Item
// DEK indirection. Used by the DragLink page to batch-encrypt / batch-decrypt
// entry metadata without client-side AES-GCM.
//
// Carve-out: HandleGroupDecryptMeta's response carries plaintext metadata —
// value (secret) plaintext is never returned by this action. HandleGroupEncrypt
// Meta's response carries only ciphertext (Base64(IV||ct)); the plaintext lives
// only in the request and briefly in Keeper memory (zeroized after sealing).

package handlers

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// HandleGroupDecryptMeta bulk-decrypts the meta fields of a group entry
// directly with the raw Group DEK behind the opaque handle. Empty ciphertext
// values are skipped. The value plaintext is never returned by this action —
// value goes through group_decrypt_to_clipboard.
func HandleGroupDecryptMeta(d Deps, req proto.GroupDecryptMetaRequest) proto.BaseResponse {
	d.Logger.Println("group decrypt meta request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	plaintextFields := map[string]string{}
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		return decryptMetaFields(groupDEK, req.MetaFields, func(name string, pt []byte) error {
			plaintextFields[name] = string(pt)
			secure.Zeroize(pt) // wipe immediately after string copy
			return nil
		})
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group decrypt meta")
	}

	d.Logger.Println("group decrypt meta successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupDecryptMetaResponseData{
		Fields: plaintextFields,
	}}
}

// HandleGroupEncryptMeta bulk-encrypts plaintext meta fields directly with the
// raw Group DEK behind the opaque handle. Each field is AES-GCM-sealed into the
// combined Base64(IV(12)||ct) form the Extension stores per meta field. Empty
// plaintext values are skipped (no ciphertext emitted), mirroring
// HandleGroupDecryptMeta's skip of empty ciphertexts. The output meta_fields is
// directly feedable back into HandleGroupDecryptMeta.
func HandleGroupEncryptMeta(d Deps, req proto.GroupEncryptMetaRequest) proto.BaseResponse {
	d.Logger.Println("group encrypt meta request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	encryptedFields := map[string]string{}
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		for name, plaintext := range req.Fields {
			if plaintext == "" {
				continue
			}
			pt := []byte(plaintext)
			sealed, err := aesGCMSeal(groupDEK, pt)
			secure.Zeroize(pt) // wipe plaintext copy right after sealing
			if err != nil {
				return errors.New("encrypt meta " + name + ": " + err.Error())
			}
			encryptedFields[name] = sealed
		}
		return nil
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "group encrypt meta")
	}

	d.Logger.Println("group encrypt meta successful")
	return proto.BaseResponse{Success: true, Data: proto.GroupEncryptMetaResponseData{
		MetaFields: encryptedFields,
	}}
}
