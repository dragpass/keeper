// group_session_models.go — Group DEK opaque handle payload.

package proto

// ────────────────────────────────────────────────────────────────────────
// Group DEK opaque handle
//
// To keep the raw Group DEK Base64 out of the Extension JS heap, Keeper holds
// it inside a memguard.LockedBuffer and exposes only a 32B random handle ID
// (Base64). All subsequent aes_* actions take GroupHandle instead of
// GroupDEKB64.
// ────────────────────────────────────────────────────────────────────────

// GroupSessionOpenRequest unwraps a wrapped Group DEK with the Keychain
// private key and registers it in the store. The raw value is not returned
// in the response — only the handle ID.
type GroupSessionOpenRequest struct {
	EncryptedGroupDEK string `json:"encrypted_group_dek"`
}

func (r GroupSessionOpenRequest) Validate() error {
	_, err := requireBase64(r.EncryptedGroupDEK, "encrypted_group_dek")
	return err
}

type GroupSessionOpenResponseData struct {
	// GroupHandle is a 32B random value (Base64). The Extension echoes it
	// verbatim on subsequent aes_* actions.
	GroupHandle string `json:"group_handle"`
	// ExpiresAtMs is in Unix milliseconds. Exposed (best-effort) so the
	// Extension can call close before expiry. The Keeper reaper still
	// guarantees cleanup after expiry.
	ExpiresAtMs int64 `json:"expires_at_ms"`
}

// GroupSessionCloseRequest explicitly disposes of a handle. Idempotent.
type GroupSessionCloseRequest struct {
	GroupHandle string `json:"group_handle"`
}

func (r GroupSessionCloseRequest) Validate() error {
	return requireHandle(r.GroupHandle, "group_handle")
}

type GroupSessionCloseResponseData struct{}

// GroupSessionStatusRequest is for debugging / observability only. Returns
// whether the handle exists and the remaining TTL in ms. Expired handles
// are lazy-evicted.
type GroupSessionStatusRequest struct {
	GroupHandle string `json:"group_handle"`
}

func (r GroupSessionStatusRequest) Validate() error {
	return requireHandle(r.GroupHandle, "group_handle")
}

type GroupSessionStatusResponseData struct {
	Exists      bool  `json:"exists"`
	RemainingMs int64 `json:"remaining_ms"`
}
