// group_encrypt_aad.go — AAD-binding variant of the raw Group DEK direct
// AES-GCM encrypt payload.
//
// GroupEncryptWithAAD is GroupEncrypt plus a required AAD: the caller-supplied
// additional authenticated data is bound into the GCM tag so the sealed payload
// is cryptographically tied to its canonical context (org_id|entry_id|
// payload_kind|schema_version|dek_version). A ciphertext sealed under one AAD
// cannot be opened under another, which prevents swap attacks. The raw Group DEK
// stays in the Keeper-side GroupSessionStore memguard buffer.

package proto

// GroupEncryptWithAADRequest seals plaintext with the raw Group DEK behind the
// opaque handle while binding AAD into the GCM tag, and returns the IV /
// ciphertext separately (reusing GroupEncryptResponseData).
type GroupEncryptWithAADRequest struct {
	GroupHandle  string `json:"group_handle"`
	PlaintextB64 string `json:"plaintext_b64"` // secret in REQUEST only; must never be logged
	AADB64       string `json:"aad_b64"`       // canonical AAD bytes, Base64; public context material
}

func (r GroupEncryptWithAADRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	// AAD is required: this action exists to bind an AAD. An empty AAD is what
	// the plain GroupEncrypt action already covers. requireBase64 rejects empty.
	if _, err := requireBase64(r.AADB64, "aad_b64"); err != nil {
		return err
	}
	return nil
}
