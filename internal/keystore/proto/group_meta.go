// group_meta.go — raw Group DEK direct batch metadata encrypt/decrypt payloads.
//
// These are the metadata-path counterparts of group_encrypt: the Item DEK
// unwrap step of aes_unwrap_and_decrypt_meta is replaced by a direct use of
// the raw Group DEK behind the opaque GroupHandle. The contracts are the
// mirror image of each other so a GroupEncryptMeta output can be fed straight
// back into GroupDecryptMeta:
//
//	GroupEncryptMeta:  {group_handle, fields}       → {meta_fields}
//	GroupDecryptMeta:  {group_handle, meta_fields}  → {fields}
//
//	fields:      key → plaintext UTF-8 string
//	meta_fields: key → Base64(IV(12) || ciphertext_with_tag)
//
// The combined Base64(IV||ct) meta-field encoding matches the Extension's
// per-field storage format (packages/crypto meta.mts) and the existing
// aes_unwrap_and_decrypt_meta / dek_unwrap_and_decrypt_meta actions.

package proto

import "errors"

// GroupDecryptMetaRequest bulk-decrypts group entry metadata fields directly
// with the raw Group DEK behind the opaque handle (no Item DEK indirection).
//
// **Carve-out:** the response carries plaintext metadata (label/url/
// hostname/...). Value (secret) plaintext is never returned by this action.
type GroupDecryptMetaRequest struct {
	GroupHandle string            `json:"group_handle"`
	MetaFields  map[string]string `json:"meta_fields"` // key → Base64(IV(12)||ct)
}

func (r GroupDecryptMetaRequest) Validate() error {
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

type GroupDecryptMetaResponseData struct {
	Fields map[string]string `json:"fields"` // key → plaintext (UTF-8)
}

// GroupEncryptMetaRequest bulk-encrypts plaintext metadata fields directly
// with the raw Group DEK behind the opaque handle. Empty plaintext values are
// skipped (they produce no ciphertext), mirroring GroupDecryptMeta's skip of
// empty ciphertext values and the Extension's null-on-empty meta convention.
type GroupEncryptMetaRequest struct {
	GroupHandle string            `json:"group_handle"`
	Fields      map[string]string `json:"fields"` // key → plaintext (UTF-8); secret in REQUEST only, never logged
}

func (r GroupEncryptMetaRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if len(r.Fields) == 0 {
		return errors.New("fields: at least one field required")
	}
	for k := range r.Fields {
		if k == "" {
			return errors.New("fields: empty key")
		}
	}
	return nil
}

type GroupEncryptMetaResponseData struct {
	MetaFields map[string]string `json:"meta_fields"` // key → Base64(IV(12)||ct), public material
}
