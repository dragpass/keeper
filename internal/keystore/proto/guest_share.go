// guest_share.go — org token → external guest share re-encryption payloads.
//
// group_transcrypt_for_guest mirrors the group_decrypt_to_clipboard input
// contract (group_handle + iv + ciphertext of a token encrypted directly with
// the raw Group DEK) but swaps the sink: instead of writing plaintext to the
// OS clipboard, the Keeper re-encrypts under a fresh one-time guest key K and
// returns only the guest ciphertext + K. Plaintext never crosses into the
// Extension JS heap.
//
// The output format is byte-compatible with the admin SPA guest viewer
// (dragpass/app/src/shared/lib/guest-share-crypto.ts):
//   - guest_ciphertext: standard Base64 of IV(12) ‖ AES-GCM(ciphertext‖tag)
//   - guest_key:        Base64URL (no padding) of the raw 32B K
// When passphrase + passphrase_salt are supplied, the AES key is
// HKDF-SHA256(ikm = K ‖ PBKDF2-SHA256(passphrase, salt, 200000, 32),
// salt = salt, info = "dragpass-guest-v1"). Otherwise K itself is the AES key.

package proto

// GroupTranscryptForGuestRequest is the request payload for
// group_transcrypt_for_guest.
//
//   - GroupHandle: handle registered via group_session_open. The raw Group
//     DEK does not live in the Extension JS heap.
//   - IVB64 / CiphertextB64: IV(12B) + ciphertext+tag of the org token,
//     decomposed by the Extension (same as group_decrypt_to_clipboard).
//   - Passphrase / PassphraseSalt: optional 2-channel strengthening. The app
//     generates the salt and sends it as standard Base64. Both must be
//     supplied together or neither — a passphrase without its salt (or vice
//     versa) is rejected. When omitted, K alone is the guest AES key.
type GroupTranscryptForGuestRequest struct {
	GroupHandle    string `json:"group_handle"`
	IVB64          string `json:"iv_b64"`
	CiphertextB64  string `json:"ciphertext_b64"`
	Passphrase     string `json:"passphrase,omitempty"`
	PassphraseSalt string `json:"passphrase_salt,omitempty"`
}

func (r GroupTranscryptForGuestRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	// passphrase and its salt travel together — the app either sends both
	// (passphrase-protected share) or neither (K-only share).
	if (r.Passphrase == "") != (r.PassphraseSalt == "") {
		return newValidationError(
			"passphrase_salt",
			"passphrase and passphrase_salt must be provided together",
		)
	}
	if r.PassphraseSalt != "" {
		if _, err := requireBase64(r.PassphraseSalt, "passphrase_salt"); err != nil {
			return err
		}
	}
	return nil
}

// GroupTranscryptForGuestResponseData carries only the guest-viewer-consumable
// outputs. **Zero plaintext / Group DEK / derived-key fields** — the response
// envelope is the source of truth for the no-echo regression guard.
type GroupTranscryptForGuestResponseData struct {
	// GuestCiphertext is standard Base64 of IV(12) ‖ AES-GCM(ct‖tag) — the
	// exact payload the guest viewer's decryptFromGuest expects.
	GuestCiphertext string `json:"guest_ciphertext"`
	// GuestKey is the raw 32B one-time key K encoded as Base64URL (no
	// padding) — the exact link-fragment encoding the guest viewer decodes.
	GuestKey string `json:"guest_key"`
}
