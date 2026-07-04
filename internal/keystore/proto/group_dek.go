// group_dek_models.go — Group DEK RSA wrap/unwrap + Recovery composites +
// admin raw-free composite action payloads.

package proto

// WrapGroupDEKRequest is the Group DEK wrap request for team
// encrypt/decrypt.
//
// GroupDEKB64:        Base64 of the raw 32B AES-GCM key the Extension
//
//	already holds. (Team creation: the newly generated Group DEK. Member
//	invite: the current Group DEK pulled from cache. Recovery re-wrap:
//	the Group DEK unwrapped with the old private key.)
//
// RecipientPublicKey: the target member's Keeper RSA public key PEM. No
//
//	Keychain access — only the PEM in the request is used (the Keeper
//	acts as a plain wrap tool).
type WrapGroupDEKRequest struct {
	GroupDEKB64        string `json:"group_dek_b64"`
	RecipientPublicKey string `json:"recipient_public_key"`
}

func (r WrapGroupDEKRequest) Validate() error {
	// Raw 32B Group DEK Base64.
	if _, err := requireBase64Len(r.GroupDEKB64, "group_dek_b64", 32); err != nil {
		return err
	}
	return requirePEM(r.RecipientPublicKey, "recipient_public_key")
}

type WrapGroupDEKResponseData struct {
	// EncryptedGroupDEK is the Base64 of the Group DEK wrapped via
	// RSA-OAEP-SHA256. Stored as-is in the server
	// group_member_deks.encrypted_group_dek.
	EncryptedGroupDEK string `json:"encrypted_group_dek"`
}

// UnwrapGroupDEKRequest decrypts encrypted_group_dek with my active
// private key in the Keychain to obtain the raw Group DEK. Needed by all
// of drag decrypt / group-member invite / Recovery re-wrap paths.
type UnwrapGroupDEKRequest struct {
	EncryptedGroupDEK string `json:"encrypted_group_dek"`
}

func (r UnwrapGroupDEKRequest) Validate() error {
	_, err := requireBase64(r.EncryptedGroupDEK, "encrypted_group_dek")
	return err
}

type UnwrapGroupDEKResponseData struct {
	// GroupDEKB64 is the Base64 of the raw 32B Group DEK. The Extension
	// imports it via Web Crypto importKey as a non-extractable CryptoKey
	// and zeroes this field immediately.
	GroupDEKB64 string `json:"group_dek_b64"`
}

// DEKRewrapWithOldKeyRequest is the request for the Recovery composite
// re-wrap action. Replaces the old `unwrapgroupdekwithkey` + WrapGroupDEK
// pair with a single Keeper-side composite action so the raw Group DEK does
// not live in the Extension JS heap.
//
// Takes a `recovery_handle` instead of the PEM. The PEM is referenced
// through the handle from the store pre-registered by recovery_session_open.
//
// NewPublicKey is the same as RecipientPublicKey in WrapGroupDEKRequest —
// the new RSA public key PEM of the re-wrap target member (usually self).
type DEKRewrapWithOldKeyRequest struct {
	ChallengeToken    string `json:"challenge_token"`
	Signature         string `json:"signature"`
	RecoveryHandle    string `json:"recovery_handle"`
	EncryptedGroupDEK string `json:"encrypted_group_dek"`
	NewPublicKey      string `json:"new_public_key"`
	ServerKeyVersion  uint   `json:"server_key_version,omitempty"` // falls back to active when 0
}

func (r DEKRewrapWithOldKeyRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.Signature, "signature"); err != nil {
		return err
	}
	if err := requireHandle(r.RecoveryHandle, "recovery_handle"); err != nil {
		return err
	}
	if _, err := requireBase64(r.EncryptedGroupDEK, "encrypted_group_dek"); err != nil {
		return err
	}
	return requirePEM(r.NewPublicKey, "new_public_key")
}

type DEKRewrapWithOldKeyResponseData struct {
	// NewEncryptedGroupDEK is the Base64 of the raw Group DEK
	// RSA-OAEP-SHA256-wrapped with the new RSA public key. Stored as-is
	// in the server group_member_deks.encrypted_group_dek.
	NewEncryptedGroupDEK string `json:"new_encrypted_group_dek"`
}

// ────────────────────────────────────────────────────────────────────────
// Group DEK raw-free composite actions
//
// Models for the 2 composite actions that keep the raw 32B Group DEK out
// of the Extension JS heap during admin actions (org/group create, member
// invite, DEK rotate).
// ────────────────────────────────────────────────────────────────────────

// GroupDEKGenerateAndOpenRequest — generates a new 32B Group DEK inside
// the Keeper, registers it with GroupSessionStore, and at the same time
// RSA-OAEP-wraps it with the caller's public key and returns the result.
// The raw bytes are never in the response and do not live in the
// Extension JS heap.
//
// Usage: adminCreateOrg / adminCreateGroup — issue a new group DEK and
// immediately wrap it with the caller's own public key to attach to the
// server createOrg/createGroup body.
type GroupDEKGenerateAndOpenRequest struct {
	MyPublicKey string `json:"my_public_key"`
}

func (r GroupDEKGenerateAndOpenRequest) Validate() error {
	return requirePEM(r.MyPublicKey, "my_public_key")
}

type GroupDEKGenerateAndOpenResponseData struct {
	GroupHandle       string `json:"group_handle"`
	ExpiresAtMs       int64  `json:"expires_at_ms"`
	EncryptedForMeB64 string `json:"encrypted_for_me_b64"`
}

// DEKRewrapForMemberRequest — unwraps my wrapped Group DEK with the
// Keychain private key and re-wraps with the peer's public key. The raw
// Group DEK lives only briefly in Keeper memory; the response includes
// only the new RSA-OAEP wrap.
//
// Usage: adminInviteMember — re-wrap my group DEK with the invitee's
// public key.
//
// The rotation member loop (adminRotateDek) would arguably be better
// served by a wrap_from_handle flow since the new raw is already in the
// store as a handle. In the current implementation we instead feed the
// encrypted_for_me_b64 from a generate_and_open response back into this
// action, producing an equivalent raw-free flow (one extra unwrap+wrap
// round-trip, but no raw exposure).
type DEKRewrapForMemberRequest struct {
	WrappedForMeB64 string `json:"wrapped_for_me_b64"`
	OtherPublicKey  string `json:"other_public_key"`
}

func (r DEKRewrapForMemberRequest) Validate() error {
	if _, err := requireBase64(r.WrappedForMeB64, "wrapped_for_me_b64"); err != nil {
		return err
	}
	return requirePEM(r.OtherPublicKey, "other_public_key")
}

type DEKRewrapForMemberResponseData struct {
	EncryptedForOtherB64 string `json:"encrypted_for_other_b64"`
}
