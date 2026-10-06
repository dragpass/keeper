// Personal DEK payloads.

package proto

// DEKGenerateAndWrapDualResponseData is the signup dual wrap's output: one
// new DEK wrapped for the password and for the device. The signup prepare
// action builds it in-process; the plaintext DEK never leaves the Keeper.
type DEKGenerateAndWrapDualResponseData struct {
	// PasswordWrappedDEKB64: Base64(salt(16) || iv(12) || ciphertext_with_tag) —
	// for server transmission. The Extension Braille-encodes it and passes
	// it to createAccount.
	PasswordWrappedDEKB64 string `json:"password_wrapped_dek_b64"`
	// DeviceWrappedDEKB64: Base64(iv(12) || ciphertext_with_tag) — for
	// local deviceMasterStorage. The Extension Braille-encodes it before
	// storing.
	DeviceWrappedDEKB64 string `json:"device_wrapped_dek_b64"`
}

// DEKRotateToDeviceKeyRequest performs the login flow's password→device
// rewrap: unwrap the password-wrapped DEK received from the server and
// rewrap it with the deviceKey. The plaintext DEK only briefly exists
// inside the Keeper memguard.
//
// deviceKey is fetched internally from the Keeper Keychain, never via the
// IPC payload.
type DEKRotateToDeviceKeyRequest struct {
	Password        string `json:"password"`
	EncryptedDEKB64 string `json:"encrypted_dek_b64"` // Base64(salt(16) || iv(12) || ct)
}

func (r DEKRotateToDeviceKeyRequest) Validate() error {
	if err := requireString(r.Password, "password"); err != nil {
		return err
	}
	_, err := requireBase64(r.EncryptedDEKB64, "encrypted_dek_b64")
	return err
}

type DEKRotateToDeviceKeyResponseData struct {
	// DeviceWrappedDEKB64: Base64(iv(12) || ciphertext_with_tag).
	// The Extension Braille-encodes it before storing in
	// deviceMasterStorage.
	DeviceWrappedDEKB64 string `json:"device_wrapped_dek_b64"`
}

// DEKUnwrapAndEncryptRequest unwraps a device-wrapped personal DEK and
// AES-GCM encrypts plaintext with it.
//   - EncryptedDEKB64: Base64(iv(12) || ciphertext_with_tag) — the raw
//     bytes the Extension decoded from the deviceMasterStorage Braille
//     value, Base64-encoded. Empty (0.0.58) uses the device-wrapped DEK
//     this Keeper keeps in its personal_device_wrapped_dek slot.
//   - PlaintextB64: Base64 of the plaintext to encrypt.
//
// deviceKey is fetched internally from the Keeper Keychain, never via the
// IPC payload.
type DEKUnwrapAndEncryptRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64,omitempty"`
	PlaintextB64    string `json:"plaintext_b64"`
}

func (r DEKUnwrapAndEncryptRequest) Validate() error {
	if err := optionalDeviceWrappedDEK(r.EncryptedDEKB64); err != nil {
		return err
	}
	_, err := requireBase64(r.PlaintextB64, "plaintext_b64")
	return err
}

type DEKUnwrapAndEncryptResponseData struct {
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// DEKRotateToNewPasswordRequest — master password change.
//
// Takes the device-wrapped DEK (raw bytes Base64 of deviceMaster) and a
// new password, then rewraps with the PBKDF2 KEK derived from the new
// password. The deviceMaster itself does not change — the caller keeps
// the same raw bytes.
type DEKRotateToNewPasswordRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64,omitempty"`
	NewPassword     string `json:"new_password"`
}

func (r DEKRotateToNewPasswordRequest) Validate() error {
	if err := optionalDeviceWrappedDEK(r.EncryptedDEKB64); err != nil {
		return err
	}
	return requireString(r.NewPassword, "new_password")
}

// DEKRotateToNewPasswordResponseData — Base64 of
// `salt(16) || iv(12) || ciphertext`. Same format as the server
// `accounts.encrypted_dek` column, so it can be PUT as-is.
type DEKRotateToNewPasswordResponseData struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
}

// optionalDeviceWrappedDEK checks the encrypted_dek_b64 of a personal dek_*
// action. Empty (0.0.58) means "the one in this Keeper's slot", which the
// handler reads; anything else must be Base64.
func optionalDeviceWrappedDEK(encryptedDEKB64 string) error {
	if encryptedDEKB64 == "" {
		return nil
	}
	_, err := requireBase64(encryptedDEKB64, "encrypted_dek_b64")
	return err
}
