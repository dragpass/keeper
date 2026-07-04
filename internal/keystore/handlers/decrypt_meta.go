// decrypt_meta.go — bulk meta-fields decrypt handler.
//
// Carve-out: response includes plaintext metadata — value (secret) plaintext
// is separated and never returned through this action.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"

	"github.com/awnumar/memguard"
)

// HandleAESUnwrapAndDecryptMeta bulk-decrypts the meta fields of a group entry.
// Item DEK unwrap → AES-GCM open each meta field → plaintext metadata in
// response. The value plaintext is never returned by this action — value goes
// through *_to_clipboard.
func HandleAESUnwrapAndDecryptMeta(d Deps, req proto.AESUnwrapAndDecryptMetaRequest) proto.BaseResponse {
	d.Logger.Println("aes unwrap and decrypt meta request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	plaintextFields := map[string]string{}
	useErr := d.GroupSessions.Use(req.GroupHandle, func(groupDEK []byte) error {
		itemDEK, err := unwrapItemDEK(groupDEK, req.WrappedItemDEK)
		if err != nil {
			return err
		}
		defer secure.Zeroize(itemDEK)

		return decryptMetaFields(itemDEK, req.MetaFields, func(name string, pt []byte) error {
			plaintextFields[name] = string(pt)
			secure.Zeroize(pt) // wipe immediately after string copy
			return nil
		})
	})
	if useErr != nil {
		return groupSessionUseError(useErr, "unwrap and decrypt meta")
	}

	d.Logger.Println("aes unwrap and decrypt meta successful")
	return proto.BaseResponse{Success: true, Data: proto.AESUnwrapAndDecryptMetaResponseData{
		Fields: plaintextFields,
	}}
}

// HandleDEKUnwrapAndDecryptMeta bulk-decrypts the meta fields of a personal entry.
// deviceKey is fetched inside the Keeper Keychain — never via the IPC payload.
func HandleDEKUnwrapAndDecryptMeta(d Deps, req proto.DEKUnwrapAndDecryptMetaRequest) proto.BaseResponse {
	d.Logger.Println("dek unwrap and decrypt meta request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	deviceKey, err := loadDeviceKeyFromKeychain(d.Store)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeStorageFailure, err.Error())
	}
	deviceKeyBuf := memguard.NewBufferFromBytes(deviceKey)
	defer deviceKeyBuf.Destroy()

	dek, err := unwrapDeviceWrappedDEK(deviceKeyBuf.Bytes(), req.EncryptedDEKB64)
	if err != nil {
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, err.Error())
	}
	defer secure.Zeroize(dek)

	plaintextFields := map[string]string{}
	if metaErr := decryptMetaFields(dek, req.MetaFields, func(name string, pt []byte) error {
		plaintextFields[name] = string(pt)
		secure.Zeroize(pt)
		return nil
	}); metaErr != nil {
		// The helper's splitErr / openErr are treated with the same classification:
		// distinguishing split failure (Validation) from AES-GCM failure
		// (CryptoFailure) is hard, so they're consolidated as CryptoFailure.
		// The old code branched between base64 vs aesGCM, but the helper preserves
		// a prefix in the message so the caller can still identify it (no
		// regression impact).
		return errs.CodeResponse(errs.ErrCodeCryptoFailure, metaErr.Error())
	}

	d.Logger.Println("dek unwrap and decrypt meta successful")
	return proto.BaseResponse{Success: true, Data: proto.DEKUnwrapAndDecryptMetaResponseData{
		Fields: plaintextFields,
	}}
}
