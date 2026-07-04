// item_dek_models.go — Item DEK AES-GCM wrap/unwrap/rewrap payloads.

package proto

import (
	"encoding/base64"
	"errors"
	"strconv"
)

// ────────────────────────────────────────────────────────────────────────
// Item DEK / personal DEK Keeper-delegated actions
//
// Handlers refer to a Group DEK by an opaque GroupHandle. The raw 32B Group
// DEK is held in a memguard.LockedBuffer by the Keeper-side GroupSessionStore,
// and handlers run AES-GCM directly on top of the buffer via Use(handle, fn).
// ────────────────────────────────────────────────────────────────────────

// AESGenerateAndWrapRequest generates a new 32B Item DEK and AES-GCM-wraps
// it with the Group DEK. Replaces the Extension's generateItemDEK +
// wrapItemDEK pair.
type AESGenerateAndWrapRequest struct {
	GroupHandle string `json:"group_handle"`
}

func (r AESGenerateAndWrapRequest) Validate() error {
	return requireHandle(r.GroupHandle, "group_handle")
}

type AESGenerateAndWrapResponseData struct {
	// ItemDEKRawB64 is the raw 32B Base64 of the newly generated Item DEK.
	// In the interim, the Extension still uses this value directly for
	// follow-up encryption; once the opaque handle migration is complete,
	// this field will be removed.
	ItemDEKRawB64 string `json:"item_dek_raw_b64"`
	// WrappedItemDEK is the Item DEK AES-GCM-wrapped with the Group DEK,
	// formatted as Base64(IV(12) || ciphertext); stored on the server in
	// item_dek_grants.wrapped_item_dek.
	WrappedItemDEK string `json:"wrapped_item_dek"`
}

// AESUnwrapAndEncryptRequest unwraps a wrapped Item DEK with the Group DEK
// and AES-GCM-encrypts plaintext. Braille encoding is the Extension's job.
// The response ciphertext includes the GCM tag.
type AESUnwrapAndEncryptRequest struct {
	WrappedItemDEK string `json:"wrapped_item_dek"`
	GroupHandle    string `json:"group_handle"`
	PlaintextB64   string `json:"plaintext_b64"` // plaintext that the Extension UTF-8 → bytes → Base64-encoded
}

func (r AESUnwrapAndEncryptRequest) Validate() error {
	if _, err := requireBase64(r.WrappedItemDEK, "wrapped_item_dek"); err != nil {
		return err
	}
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	return nil
}

type AESUnwrapAndEncryptResponseData struct {
	IVB64         string `json:"iv_b64"`         // 12B IV Base64
	CiphertextB64 string `json:"ciphertext_b64"` // ciphertext + GCM tag Base64
}

// The AESUnwrapAndDecrypt action was removed. Replacements:
// AESUnwrapAndDecryptToClipboard (clipboard sink) /
// AESUnwrapAndDecryptMeta (metadata batch decrypt, carve-out).

// AESRewrap (cross-group Item DEK rewrap) was removed alongside the
// item_dek_grants schema. Metadata-only DragLink does not carry a wrapped
// Item DEK; cross-group share is not possible at the server layer.

// AESUnshareRewrapMetaRequest is the input for the composite
// UNSHARE_REENCRYPT action.
type AESUnshareRewrapMetaRequest struct {
	WrappedItemDEK       string            `json:"wrapped_item_dek"`
	SrcGroupHandle       string            `json:"src_group_handle"`
	IVB64                string            `json:"iv_b64"`
	CiphertextB64        string            `json:"ciphertext_b64"`
	MetaFields           map[string]string `json:"meta_fields,omitempty"`             // key → Base64(IV(12)||ct)
	ExtraDstGroupHandles []string          `json:"extra_dst_group_handles,omitempty"` // additional group handles beyond src
}

// SplitMetaCipherInline splits a Base64(IV(12)||ct) meta ciphertext into
// an IV/ct pair. An empty string or fewer than 12 bytes is invalid. Used
// by §B-1, §C-1, and §C-2 alike.
func SplitMetaCipherInline(b64 string) ([]byte, []byte, error) {
	if b64 == "" {
		return nil, nil, errors.New("meta cipher empty")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, errors.New("meta cipher base64 decode: " + err.Error())
	}
	if len(raw) < 12 {
		return nil, nil, errors.New("meta cipher too short (< 12B IV)")
	}
	return raw[:12], raw[12:], nil
}

func (r AESUnshareRewrapMetaRequest) Validate() error {
	if _, err := requireBase64(r.WrappedItemDEK, "wrapped_item_dek"); err != nil {
		return err
	}
	if err := requireHandle(r.SrcGroupHandle, "src_group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	for k, v := range r.MetaFields {
		if k == "" {
			return errors.New("meta_fields: empty key")
		}
		if v == "" {
			continue
		}
		if _, _, err := SplitMetaCipherInline(v); err != nil {
			return errors.New("meta_fields[" + k + "]: " + err.Error())
		}
	}
	for i, h := range r.ExtraDstGroupHandles {
		if err := requireHandle(h, "extra_dst_group_handles"); err != nil {
			return errors.New("extra_dst_group_handles[" + strconv.Itoa(i) + "]: " + err.Error())
		}
	}
	return nil
}

// AESUnshareRewrapMetaGrant is the result of wrapping a new Item DEK with
// one group's Group DEK.
type AESUnshareRewrapMetaGrant struct {
	GroupHandle    string `json:"group_handle"`
	WrappedItemDEK string `json:"wrapped_item_dek"`
}

// AESUnshareRewrapMetaResponseData is the response envelope.
type AESUnshareRewrapMetaResponseData struct {
	NewEncryptedValue  string                      `json:"new_encrypted_value"`            // Base64(IV(12)||ct)
	NewEncryptedFields map[string]string           `json:"new_encrypted_fields,omitempty"` // key → Base64(IV(12)||ct)
	NewGrants          []AESUnshareRewrapMetaGrant `json:"new_grants"`                     // includes both src and extra dst
}

// AESUnwrapAndDecryptMetaRequest is the bulk-decrypt action for group entry
// metadata fields.
//
// **Carve-out:** the response carries plaintext metadata (label/url/
// hostname/field_type/...). Value plaintext is never returned by this
// action.
type AESUnwrapAndDecryptMetaRequest struct {
	WrappedItemDEK string            `json:"wrapped_item_dek"`
	GroupHandle    string            `json:"group_handle"`
	MetaFields     map[string]string `json:"meta_fields"`
}

func (r AESUnwrapAndDecryptMetaRequest) Validate() error {
	if _, err := requireBase64(r.WrappedItemDEK, "wrapped_item_dek"); err != nil {
		return err
	}
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if len(r.MetaFields) == 0 {
		return errors.New("meta_fields: at least one field required")
	}
	for k, v := range r.MetaFields {
		if k == "" {
			return errors.New("meta_fields: empty key")
		}
		if v == "" {
			continue
		}
		if _, _, err := SplitMetaCipherInline(v); err != nil {
			return errors.New("meta_fields[" + k + "]: " + err.Error())
		}
	}
	return nil
}

type AESUnwrapAndDecryptMetaResponseData struct {
	Fields map[string]string `json:"fields"` // key → plaintext (UTF-8)
}
