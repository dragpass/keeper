// personal_dek_models.go — personal DEK generate / wrap / rotate / encrypt /
// decrypt payloads.

package proto

import "errors"

// DEKGenerateAndWrapPasswordRequest moves the signup flow's generateDEK +
// wrapDEKWithPassword into the Keeper. The output EncryptedDEKB64 is
// Base64(SALT(16) || IV(12) || ciphertext_with_tag); the Extension Braille-
// encodes it via encodeToVisualBlock before storing on the server.
//
// PBKDF2 parameters match the Extension's deriveKeyForWrapping:
//   - SHA-256, 600,000 iterations, salt 16B, IV 12B, AES-256-GCM
type DEKGenerateAndWrapPasswordRequest struct {
	Password string `json:"password"`
}

func (r DEKGenerateAndWrapPasswordRequest) Validate() error {
	return requireString(r.Password, "password")
}

type DEKGenerateAndWrapPasswordResponseData struct {
	// EncryptedDEKB64 is Base64(salt(16) || iv(12) || ciphertext_with_tag).
	// The Extension Braille-encodes this value as-is.
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
}

// DEKGenerateAndWrapDualRequest generates a new DEK at signup and wraps it
// with both password and deviceKey in one shot. The Extension never sees
// plaintext DEK.
//
// deviceKey is fetched directly from the Keeper Keychain rather than via the
// IPC payload, so the raw key never crosses the process boundary.
type DEKGenerateAndWrapDualRequest struct {
	Password string `json:"password"`
}

func (r DEKGenerateAndWrapDualRequest) Validate() error {
	return requireString(r.Password, "password")
}

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
//     value, Base64-encoded.
//   - PlaintextB64: Base64 of the plaintext to encrypt.
//
// deviceKey is fetched internally from the Keeper Keychain, never via the
// IPC payload.
type DEKUnwrapAndEncryptRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
	PlaintextB64    string `json:"plaintext_b64"`
}

func (r DEKUnwrapAndEncryptRequest) Validate() error {
	if _, err := requireBase64(r.EncryptedDEKB64, "encrypted_dek_b64"); err != nil {
		return err
	}
	_, err := requireBase64(r.PlaintextB64, "plaintext_b64")
	return err
}

type DEKUnwrapAndEncryptResponseData struct {
	IVB64         string `json:"iv_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

// The DEKUnwrapAndDecrypt action was removed. Replacements:
// DEKUnwrapAndDecryptToClipboard (clipboard sink) / DEKUnwrapAndDecryptMeta
// (metadata batch decrypt, carve-out).

// DEKUnwrapAndDecryptMetaRequest is the bulk-decrypt action for personal
// entry metadata fields.
//
// **Carve-out:** the response carries plaintext metadata. This is an
// intentional exception to the zero-extractable model, for user-visible
// search / filter / display purposes — value (secret) plaintext is never
// returned by this action.
//
// Input meta_fields: key → Base64(IV(12)||ciphertext)
// Response fields:   key → plaintext string (UTF-8)
//
// deviceKey is fetched internally from the Keeper Keychain.
type DEKUnwrapAndDecryptMetaRequest struct {
	EncryptedDEKB64 string            `json:"encrypted_dek_b64"`
	MetaFields      map[string]string `json:"meta_fields"`
}

func (r DEKUnwrapAndDecryptMetaRequest) Validate() error {
	if _, err := requireBase64(r.EncryptedDEKB64, "encrypted_dek_b64"); err != nil {
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

type DEKUnwrapAndDecryptMetaResponseData struct {
	Fields map[string]string `json:"fields"` // key → plaintext (UTF-8)
}

// DEKRotateToNewPasswordRequest — master password change.
//
// Takes the device-wrapped DEK (raw bytes Base64 of deviceMaster) and a
// new password, then rewraps with the PBKDF2 KEK derived from the new
// password. The deviceMaster itself does not change — the caller keeps
// the same raw bytes.
type DEKRotateToNewPasswordRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
	NewPassword     string `json:"new_password"`
}

func (r DEKRotateToNewPasswordRequest) Validate() error {
	if err := requireString(r.EncryptedDEKB64, "encrypted_dek_b64"); err != nil {
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
