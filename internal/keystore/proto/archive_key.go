// archive_key.go — per-org Archive / Recovery keypair payloads.
//
//   - archive_key_generate : generate an RSA archive keypair if none exists.
//     Idempotent — when an active key is already present, return only its meta.
//   - archive_key_status   : whether an active archive key exists + public key.
//
// The archive keypair is an org break-glass recovery key. Its private key lives
// only in the org_archive_private_key keychain slot and is never used for
// identity / login / recovery / request signing.
//
// publickey is an RSA public-key PEM string. fingerprint is
// hex(sha256(publickey PEM)) — the same identifier the server and Extension
// derive for the archive grant's recipient_key_fingerprint.

package proto

type ArchiveKeyGenerateRequest struct{}

func (r ArchiveKeyGenerateRequest) Validate() error { return nil }

type ArchiveKeyGenerateResponseData struct {
	PublicKey   string `json:"publickey"`   // RSA public key PEM
	Fingerprint string `json:"fingerprint"` // hex(sha256(public key PEM))
}

type ArchiveKeyStatusRequest struct{}

func (r ArchiveKeyStatusRequest) Validate() error { return nil }

type ArchiveKeyStatusResponseData struct {
	HasActive   bool   `json:"has_active"`
	PublicKey   string `json:"publickey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Same-device org archive key rotation (staging-slot pattern). begin stages a
// new keypair, commit promotes it, abort discards it. All three carry an empty
// request; responses expose only public material.

type ArchiveKeyRotateBeginRequest struct{}

func (r ArchiveKeyRotateBeginRequest) Validate() error { return nil }

type ArchiveKeyRotateBeginResponseData struct {
	PublicKey   string `json:"publickey"`   // NEW (staged) RSA public key PEM
	Fingerprint string `json:"fingerprint"` // hex(sha256(public key PEM))
}

type ArchiveKeyRotateCommitRequest struct{}

func (r ArchiveKeyRotateCommitRequest) Validate() error { return nil }

type ArchiveKeyRotateCommitResponseData struct {
	Fingerprint string `json:"fingerprint"` // promoted (now active) key fingerprint
}

type ArchiveKeyRotateAbortRequest struct{}

func (r ArchiveKeyRotateAbortRequest) Validate() error { return nil }

type ArchiveKeyRotateAbortResponseData struct {
	Aborted bool `json:"aborted"` // true if a staging key was discarded, false if none
}

// Per-account Archive / Recovery receiving keypair (dedicated slot, separate
// from the org archive keypair). Same idempotent generate / status contract as
// the org actions, but against the account slot: this is the key published to
// the server account directory (account_archive_keys) and the one that
// receives ownership-handoff grants and archive quorum Shamir shares. It
// survives the org-slot wipe performed by archive_key_split.

type AccountArchiveKeyGenerateRequest struct{}

func (r AccountArchiveKeyGenerateRequest) Validate() error { return nil }

type AccountArchiveKeyGenerateResponseData struct {
	PublicKey   string `json:"publickey"`   // RSA public key PEM
	Fingerprint string `json:"fingerprint"` // hex(sha256(public key PEM))
}

type AccountArchiveKeyStatusRequest struct{}

func (r AccountArchiveKeyStatusRequest) Validate() error { return nil }

type AccountArchiveKeyStatusResponseData struct {
	HasActive   bool   `json:"has_active"`
	PublicKey   string `json:"publickey,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ArchiveUnwrapAndRewrapRequest — break-glass re-grant composite.
//
// WrappedForArchiveB64: Base64 of an OLD Group DEK RSA-OAEP-wrapped to the org
//
//	archive public key (the org_owner_archive grant's encrypted_group_dek).
//
// RecipientPublicKey: the target member's Keeper RSA public key PEM, the
//
//	re-grant recipient. The raw Group DEK is unwrapped with the archive
//	private key (org slot first; on decrypt failure the account archive slot
//	is tried, covering handoff-received grants wrapped to the account
//	directory key) and re-wrapped to this key; the response carries only the
//	new wrap.
type ArchiveUnwrapAndRewrapRequest struct {
	WrappedForArchiveB64 string `json:"wrapped_for_archive_b64"`
	RecipientPublicKey   string `json:"recipient_public_key"`
}

func (r ArchiveUnwrapAndRewrapRequest) Validate() error {
	if _, err := requireBase64(r.WrappedForArchiveB64, "wrapped_for_archive_b64"); err != nil {
		return err
	}
	return requirePEM(r.RecipientPublicKey, "recipient_public_key")
}

type ArchiveUnwrapAndRewrapResponseData struct {
	EncryptedForOtherB64 string `json:"encrypted_for_other_b64"`
}
