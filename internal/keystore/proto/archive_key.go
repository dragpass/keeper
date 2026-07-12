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

// ArchiveUnwrapAndRewrapRequest — break-glass re-grant composite.
//
// WrappedForArchiveB64: Base64 of an OLD Group DEK RSA-OAEP-wrapped to the org
//
//	archive public key (the org_owner_archive grant's encrypted_group_dek).
//
// RecipientPublicKey: the target member's Keeper RSA public key PEM, the
//
//	re-grant recipient. The raw Group DEK is unwrapped with the archive
//	private key (dedicated slot, never leaves) and re-wrapped to this key; the
//	response carries only the new wrap.
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
