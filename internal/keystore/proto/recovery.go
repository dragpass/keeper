// recovery_models.go — Recovery flow payloads.
// RecoverySign / GenerateKeypairWithRecoveryWrap / RecoverySessionOpen /
// RecoverySessionClose request/response.

package proto

// RecoverySignRequest asks the Keeper to sign the challenge_token with the
// old Keeper private key during the Recovery flow.
//
// Takes a `recovery_handle` instead of the PEM. The handle is issued in
// advance via `recovery_session_open` and points at a PEM held inside
// Keeper memguard. The PEM does not live in the Extension JS heap and is
// not passed as IPC payload.
//
// The signature field is the server's signature over challenge_token; the
// Keeper verifies it with the server public key to confirm "this
// challenge_token was actually issued by the server" (replay/spoof
// guard). recovery_session_open already verifies the challenge, so this
// is technically redundant — but it preserves per-action origin
// verification and blocks scenarios where a handle is reused for a
// different challenge.
type RecoverySignRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`                    // server signature over challenge_token
	RecoveryHandle   string `json:"recovery_handle"`              // result of recovery_session_open
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r RecoverySignRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	return requireHandle(r.RecoveryHandle, "recovery_handle")
}

type RecoverySignResponseData struct {
	Signature string `json:"signature"` // signature over challenge_token by the old private key (Base64)
}

// GenerateKeypairWithRecoveryWrapRequest is called right before Recovery
// Complete: generate a new RSA keypair and immediately wrap the private
// key with wrap_key via AES-GCM, then return the wrapped result. The
// Extension never sees the plaintext private key.
//
// The new keypair is stored in the Keychain as active, while the wrapped
// result is sent to the server as recovery_wrapped_keeper for future
// recovery.
//
// wrap_key is the Base64 of the raw bytes (32B AES-GCM key) that the
// client derived from the RK24 HKDF wrap path (after PBKDF2).
type GenerateKeypairWithRecoveryWrapRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`                    // server signature over challenge_token
	WrapKeyB64       string `json:"wrap_key_b64"`                 // Base64 of a 32B raw AES-GCM key
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r GenerateKeypairWithRecoveryWrapRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	// wrap_key is the Base64 of a 32B AES-GCM raw key (Recovery RK24 wrap
	// path).
	_, err := requireBase64Len(r.WrapKeyB64, "wrap_key_b64", 32)
	return err
}

type GenerateKeypairWithRecoveryWrapResponseData struct {
	PublicKey     string `json:"publickey"`
	WrappedKeeper string `json:"wrapped_keeper"` // private key AES-GCM-wrapped with wrap_key (Base64: iv || ciphertext)
}

// ────────────────────────────────────────────────────────────────────────
// Recovery old PEM opaque handle
//
// Closes the surface where the old Keeper RSA private-key PEM would
// otherwise live as a string in the Extension JS heap during Recovery.
// The Keeper takes wrappedKeeper + wrap_key, unwraps internally → keeps in
// memguard → issues a handle. Subsequent recoverysign /
// dek_rewrap_with_old_key operate on PEM bytes via the handle.
// ────────────────────────────────────────────────────────────────────────

// RecoverySessionOpenRequest — the Extension sends both the wrap_key it
// derived via the RK24 wrap path and the server response's wrappedKeeper
// (Base64 IV||ciphertext). challenge_token + server signature verify the
// Recovery context.
type RecoverySessionOpenRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	Signature        string `json:"signature"`
	WrappedKeeperB64 string `json:"wrapped_keeper_b64"`
	WrapKeyB64       string `json:"wrap_key_b64"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r RecoverySessionOpenRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	if _, err := requireBase64(r.WrappedKeeperB64, "wrapped_keeper_b64"); err != nil {
		return err
	}
	// wrap_key is the Base64 of a 32B AES-GCM raw key.
	_, err := requireBase64Len(r.WrapKeyB64, "wrap_key_b64", 32)
	return err
}

type RecoverySessionOpenResponseData struct {
	RecoveryHandle string `json:"recovery_handle"`
	ExpiresAtMs    int64  `json:"expires_at_ms"`
}

type RecoverySessionCloseRequest struct {
	RecoveryHandle string `json:"recovery_handle"`
}

func (r RecoverySessionCloseRequest) Validate() error {
	return requireHandle(r.RecoveryHandle, "recovery_handle")
}

type RecoverySessionCloseResponseData struct{}

// WrapActivePrivateKeyRequest — Recovery key re-issue.
// Called when the user re-issues an RK24. Returns the current active
// Keeper privkey AES-GCM-wrapped with the supplied wrap_key — the keypair
// itself does not change.
//
// Auth model: Native Messaging trust as-is (only the locked Extension
// manifest ID can talk to the Keeper). No separate challenge-response —
// the user already has an access token, and the admin SPA modal's
// type-to-confirm verifies intent.
type WrapActivePrivateKeyRequest struct {
	WrapKeyB64 string `json:"wrap_key_b64"` // Base64 of a 32B raw AES-GCM key
}

func (r WrapActivePrivateKeyRequest) Validate() error {
	_, err := requireBase64Len(r.WrapKeyB64, "wrap_key_b64", 32)
	return err
}

// WrapActivePrivateKeyResponseData — Base64 of the PEM AES-GCM-wrapped
// with wrap_key (IV(12) || ciphertext_with_tag). Stored as-is in the
// server `recovery_wrapped_keeper` column.
type WrapActivePrivateKeyResponseData struct {
	WrappedKeeperB64 string `json:"wrapped_keeper_b64"`
}
