// personal_dek_aad.go — AAD-binding variant of the personal DEK direct
// AES-GCM encrypt payload.
//
// DEKUnwrapAndEncryptWithAAD is DEKUnwrapAndEncrypt plus a required AAD: the
// caller-supplied additional authenticated data is bound into the GCM tag so
// the sealed payload is cryptographically tied to its canonical context
// (account_id|entry_id|payload_kind|schema_version|dek_version). A ciphertext
// sealed under one AAD cannot be opened under another, which prevents swap
// attacks.
//
// This is the personal-scope sibling of GroupEncryptWithAAD. The difference is
// only which key seals: the group variant uses the raw Group DEK behind an
// opaque session handle, this one unwraps the device-wrapped personal DEK the
// same way DEKUnwrapAndEncrypt does. The AAD contract is identical — canonical
// context bytes supplied by the caller, public material, never secret.

package proto

// DEKUnwrapAndEncryptWithAADRequest unwraps a device-wrapped personal DEK and
// AES-GCM-seals plaintext with it while binding AAD into the GCM tag. Reuses
// DEKUnwrapAndEncryptResponseData for the {iv_b64, ciphertext_b64} response.
//
// deviceKey is fetched internally from the Keeper Keychain, never via the IPC
// payload — same as the non-AAD variant.
type DEKUnwrapAndEncryptWithAADRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
	PlaintextB64    string `json:"plaintext_b64"` // secret in REQUEST only; must never be logged
	AADB64          string `json:"aad_b64"`       // canonical AAD bytes, Base64; public context material
}

func (r DEKUnwrapAndEncryptWithAADRequest) Validate() error {
	if _, err := requireBase64(r.EncryptedDEKB64, "encrypted_dek_b64"); err != nil {
		return err
	}
	if _, err := requireBase64(r.PlaintextB64, "plaintext_b64"); err != nil {
		return err
	}
	// AAD is required: this action exists to bind an AAD. An empty AAD is what
	// the plain DEKUnwrapAndEncrypt action already covers. requireBase64
	// rejects empty.
	if _, err := requireBase64(r.AADB64, "aad_b64"); err != nil {
		return err
	}
	return nil
}
