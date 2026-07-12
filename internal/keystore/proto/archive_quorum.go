// archive_quorum.go — payloads for the org archive-key admin quorum
// (Shamir N-of-M break-glass) actions.
//
//   - archive_key_split  : Shamir-split the org archive private key into M
//     shares, hybrid-wrap each to an admin's account archive public key, then
//     delete the whole private key. At rest the key exists only as shares.
//   - archive_session_begin / _end : create/destroy the coordinator's
//     ephemeral recovery-session keypair.
//   - archive_share_rewrap : an admin re-wraps their own share from their
//     account archive key to the session public key so the coordinator can
//     combine it.
//   - archive_quorum_combine_and_rewrap : the coordinator unwraps N re-wrapped
//     shares with the session private key, reconstructs the archive private
//     key, unwraps the OLD Group DEK, and re-wraps it to the target members.
//     All key material is wiped before returning.
//
// Shares are ~1.7 KB (a Shamir share of the archive private-key PEM), far above
// the RSA-OAEP plaintext limit, so every share is transported as a hybrid
// envelope: wrapped_key = RSA-OAEP(AES key), ciphertext = AES-GCM(share).

package proto

import "fmt"

// WrappedShare is one hybrid-wrapped Shamir share in the split output. The
// share's x-coordinate is embedded (authenticated) inside the ciphertext;
// share_index is echoed as metadata so the server can index shares per admin.
type WrappedShare struct {
	ShareIndex           int    `json:"share_index"`
	WrappedKey           string `json:"wrapped_key"`           // Base64 RSA-OAEP(AES key)
	Ciphertext           string `json:"ciphertext"`            // Base64 IV||AES-GCM(share)
	RecipientFingerprint string `json:"recipient_fingerprint"` // hex(sha256(recipient PEM))
}

// ArchiveKeySplitRequest — threshold_n of len(recipient_public_keys) split.
// Each recipient PEM is an admin's account archive public key (the coordinator
// may include their own).
type ArchiveKeySplitRequest struct {
	ThresholdN          int      `json:"threshold_n"`
	RecipientPublicKeys []string `json:"recipient_public_keys"`
}

func (r ArchiveKeySplitRequest) Validate() error {
	if r.ThresholdN < 2 {
		return newValidationError("threshold_n", "must be >= 2")
	}
	if len(r.RecipientPublicKeys) < r.ThresholdN {
		return newValidationError("recipient_public_keys", "must have at least threshold_n entries")
	}
	if len(r.RecipientPublicKeys) > 255 {
		return newValidationError("recipient_public_keys", "must have at most 255 entries")
	}
	for i, pem := range r.RecipientPublicKeys {
		if err := requirePEM(pem, fmt.Sprintf("recipient_public_keys[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

type ArchiveKeySplitResponseData struct {
	// KeyFingerprint is hex(sha256(public key PEM)) of the key that was split,
	// derived from the private key itself. The server verifies it against the
	// org's active archive key so shares of a wrong / stale key are rejected
	// at setup instead of being discovered at recovery time.
	KeyFingerprint string         `json:"key_fingerprint"`
	Shares         []WrappedShare `json:"shares"`
}

// ArchiveShareRewrapRequest — an admin re-wraps their own hybrid-wrapped share
// (currently under their account archive key) to the recovery session key.
type ArchiveShareRewrapRequest struct {
	WrappedKey       string `json:"wrapped_key"`
	Ciphertext       string `json:"ciphertext"`
	SessionPublicKey string `json:"session_public_key"`
}

func (r ArchiveShareRewrapRequest) Validate() error {
	if _, err := requireBase64(r.WrappedKey, "wrapped_key"); err != nil {
		return err
	}
	if _, err := requireBase64(r.Ciphertext, "ciphertext"); err != nil {
		return err
	}
	return requirePEM(r.SessionPublicKey, "session_public_key")
}

type ArchiveShareRewrapResponseData struct {
	WrappedKey string `json:"wrapped_key"`
	Ciphertext string `json:"ciphertext"`
}

// ArchiveSessionBeginRequest — generate the coordinator's ephemeral
// recovery-session keypair and return its public key.
type ArchiveSessionBeginRequest struct{}

func (r ArchiveSessionBeginRequest) Validate() error { return nil }

type ArchiveSessionBeginResponseData struct {
	SessionPublicKey string `json:"session_public_key"`
	Fingerprint      string `json:"fingerprint"`
}

// ArchiveSessionEndRequest — destroy the recovery-session keypair. Idempotent.
type ArchiveSessionEndRequest struct{}

func (r ArchiveSessionEndRequest) Validate() error { return nil }

type ArchiveSessionEndResponseData struct {
	Ended bool `json:"ended"`
}

// RewrappedShareInput — one share re-wrapped to the session public key, as
// submitted by an approving admin. The x-coordinate is inside the ciphertext.
type RewrappedShareInput struct {
	WrappedKey string `json:"wrapped_key"`
	Ciphertext string `json:"ciphertext"`
}

// ArchiveQuorumCombineAndRewrapRequest — coordinator combine + re-grant.
//
//	RewrappedShares: >= threshold shares, each hybrid-wrapped to the session
//	                 public key (unwrappable with the session private slot).
//	WrappedOldDEKB64: OLD Group DEK RSA-OAEP-wrapped to the archive public key
//	                 (the org_owner_archive grant's encrypted_group_dek).
//	RecipientPublicKeys: target members' Keeper public keys — the re-grant
//	                 recipients.
type ArchiveQuorumCombineAndRewrapRequest struct {
	RewrappedShares     []RewrappedShareInput `json:"rewrapped_shares"`
	WrappedOldDEKB64    string                `json:"wrapped_old_dek_b64"`
	RecipientPublicKeys []string              `json:"recipient_public_keys"`
}

func (r ArchiveQuorumCombineAndRewrapRequest) Validate() error {
	if len(r.RewrappedShares) < 2 {
		return newValidationError("rewrapped_shares", "must have at least 2 shares")
	}
	for i, s := range r.RewrappedShares {
		if _, err := requireBase64(s.WrappedKey, fmt.Sprintf("rewrapped_shares[%d].wrapped_key", i)); err != nil {
			return err
		}
		if _, err := requireBase64(s.Ciphertext, fmt.Sprintf("rewrapped_shares[%d].ciphertext", i)); err != nil {
			return err
		}
	}
	if _, err := requireBase64(r.WrappedOldDEKB64, "wrapped_old_dek_b64"); err != nil {
		return err
	}
	if len(r.RecipientPublicKeys) == 0 {
		return newValidationError("recipient_public_keys", "must not be empty")
	}
	for i, pem := range r.RecipientPublicKeys {
		if err := requirePEM(pem, fmt.Sprintf("recipient_public_keys[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// QuorumRewrapGrant — one re-grant produced by combine, parallel to a recipient.
type QuorumRewrapGrant struct {
	RecipientFingerprint string `json:"recipient_fingerprint"`
	EncryptedGroupDEKB64 string `json:"encrypted_group_dek_b64"`
}

type ArchiveQuorumCombineAndRewrapResponseData struct {
	Grants []QuorumRewrapGrant `json:"grants"`
}
