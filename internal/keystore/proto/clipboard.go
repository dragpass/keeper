// clipboard.go — decrypt-to-clipboard request/response payloads.
//
// See security/keeper-plaintext-command-api-plan.md "API Design" section.
// Neither action's response includes plaintext / plaintext_b64 / preview /
// length metadata — only the copied flag + clipboard_ttl_ms.

package proto

const (
	// ClipboardTTLMinMs / MaxMs — Keeper-owned TTL allowed range (5s ~ 60s).
	// Blocks extremes like 0 (immediate erase) or 24h.
	ClipboardTTLMinMs int64 = 5_000
	ClipboardTTLMaxMs int64 = 60_000
)

// DEKUnwrapAndDecryptToClipboardRequest is the request payload for the
// action where the Keeper writes personal-DEK plaintext directly to the
// OS clipboard. The input signature matches the original
// DEKUnwrapAndDecryptRequest plus clipboard_ttl_ms.
type DEKUnwrapAndDecryptToClipboardRequest struct {
	EncryptedDEKB64 string `json:"encrypted_dek_b64"`
	IVB64           string `json:"iv_b64"`
	CiphertextB64   string `json:"ciphertext_b64"`
	ClipboardTTLMs  int64  `json:"clipboard_ttl_ms"`
}

func (r DEKUnwrapAndDecryptToClipboardRequest) Validate() error {
	if _, err := requireBase64(r.EncryptedDEKB64, "encrypted_dek_b64"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	return validateClipboardTTL(r.ClipboardTTLMs)
}

// AESUnwrapAndDecryptToClipboardRequest is the request payload for the
// action where the Keeper writes group-item plaintext directly to the OS
// clipboard. The input signature matches the original
// AESUnwrapAndDecryptRequest plus clipboard_ttl_ms.
type AESUnwrapAndDecryptToClipboardRequest struct {
	WrappedItemDEK string `json:"wrapped_item_dek"`
	GroupHandle    string `json:"group_handle"`
	IVB64          string `json:"iv_b64"`
	CiphertextB64  string `json:"ciphertext_b64"`
	ClipboardTTLMs int64  `json:"clipboard_ttl_ms"`
}

func (r AESUnwrapAndDecryptToClipboardRequest) Validate() error {
	if _, err := requireBase64(r.WrappedItemDEK, "wrapped_item_dek"); err != nil {
		return err
	}
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	return validateClipboardTTL(r.ClipboardTTLMs)
}

// GroupDecryptToClipboardRequest is the request payload for the action
// where the Keeper writes drag / audit token plaintext directly to the
// OS clipboard. Handles tokens encrypted with the raw Group DEK directly
// — not DragLink Item DEK tokens (which use an AES-wrapped Item DEK).
//
// Input signature:
//   - GroupHandle: handle registered via group_session_open. The raw
//     Group DEK does not live in the Extension JS heap.
//   - IVB64 / CiphertextB64: IV(12B) + ciphertext+tag, decomposed from
//     the token. The Extension has already handled shuffle Braille
//     decoding (and a second shuffle for audit mode).
//   - ClipboardTTLMs: 5000~60000.
//
// **When used:** REGISTRY_DECRYPT's group/audit branch and the
// context-menu "decrypt and copy" group/audit branch.
type GroupDecryptToClipboardRequest struct {
	GroupHandle    string `json:"group_handle"`
	IVB64          string `json:"iv_b64"`
	CiphertextB64  string `json:"ciphertext_b64"`
	ClipboardTTLMs int64  `json:"clipboard_ttl_ms"`
}

func (r GroupDecryptToClipboardRequest) Validate() error {
	if err := requireHandle(r.GroupHandle, "group_handle"); err != nil {
		return err
	}
	if _, err := requireBase64Len(r.IVB64, "iv_b64", 12); err != nil {
		return err
	}
	if _, err := requireBase64(r.CiphertextB64, "ciphertext_b64"); err != nil {
		return err
	}
	return validateClipboardTTL(r.ClipboardTTLMs)
}

// ClipboardCopyResponseData is the common response for to_clipboard
// actions.
//
// **Zero plaintext / plaintext_b64 / preview / length metadata.** The
// response envelope itself is the single source of truth for the
// plaintext-echo regression guard.
type ClipboardCopyResponseData struct {
	Copied         bool  `json:"copied"`
	ClipboardTTLMs int64 `json:"clipboard_ttl_ms"`
}

func validateClipboardTTL(ms int64) error {
	if ms < ClipboardTTLMinMs || ms > ClipboardTTLMaxMs {
		return newValidationError("clipboard_ttl_ms", "out of allowed range (5000~60000)")
	}
	return nil
}

// ClipboardGetLastHashRequest is a test-only action. No payload.
type ClipboardGetLastHashRequest struct{}

func (r ClipboardGetLastHashRequest) Validate() error { return nil }

// ClipboardGetLastHashResponseData exposes MemoryClipboard records.
// Plaintext is never included — only the SHA-256 hash + write count +
// last TTL.
type ClipboardGetLastHashResponseData struct {
	HasHash     bool   `json:"has_hash"`
	LastHashB64 string `json:"last_hash_b64"`
	WriteCount  int    `json:"write_count"`
	LastTTLMs   int64  `json:"last_ttl_ms"`
}
