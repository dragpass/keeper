// group_encrypt.go — raw Group DEK direct AES-GCM encrypt payloads.
//
// GroupEncrypt is the encrypt-direction mirror of GroupDecryptToClipboard:
// it seals plaintext directly under the raw Group DEK behind the opaque
// GroupHandle, with no Item DEK indirection. The raw Group DEK stays in the
// Keeper-side GroupSessionStore memguard buffer.

package proto

// GroupEncryptRequest seals plaintext directly with the raw Group DEK behind
// the opaque handle and returns the IV / ciphertext separately.
type GroupEncryptRequest struct {
	GroupHandle  string `json:"group_handle"`
	PlaintextB64 string `json:"plaintext_b64"` // secret in REQUEST only; must never be logged
}

func (r GroupEncryptRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	return nil
}

type GroupEncryptResponseData struct {
	IVB64         string `json:"iv_b64"`         // 12B IV, public material
	CiphertextB64 string `json:"ciphertext_b64"` // ciphertext + GCM tag, public material
}
