// mls_leaf.go — the MLS leaf declaration (chat v2, form A).
//
// A declaration is how an account vouches for one of its devices' MLS leaf
// signature keys. It is signed with the account identity key, the key peers
// already pin, so accepting a leaf becomes a question the pin state machine
// already answers instead of a new root of trust.
//
// Every field names a device, not an account. Only one leaf per account exists
// today, but a verifier never learns that from this format.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/dragpass-chat-v2-mls-integration.md §5.2, §5.3, §12.2.

package proto

import (
	"strconv"
	"strings"
)

const (
	// MLSLeafCanonicalDomain keeps a declaration signature from verifying as
	// any other `dragpass.` statement signed by the same account key.
	MLSLeafCanonicalDomain = "dragpass.mls.leaf"

	MLSLeafCanonicalVersion = 1

	// There is no revoke: a `rotate` declaration supersedes the previous one
	// for the same device (M1.5).
	MLSLeafReasonEnroll = "enroll"
	MLSLeafReasonRotate = "rotate"
)

// MLSLeafDeclaration is the signed statement as it crosses the wire.
// SignatureKey is the raw 32-byte Ed25519 public key in standard Base64, so the
// fingerprint is recomputable from the declaration alone.
type MLSLeafDeclaration struct {
	AccountID               string `json:"account_id"`
	DeviceID                string `json:"device_id"`
	SignatureKey            string `json:"signature_key"`
	SignatureKeyFingerprint string `json:"signature_key_fingerprint"`
	NotBefore               int64  `json:"not_before"`
	Reason                  string `json:"reason"`
	Signature               string `json:"signature"`
}

func (d MLSLeafDeclaration) Canonical() string {
	return MLSLeafCanonical(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.Reason)
}

// MLSLeafCanonical renders the signing string. ariadne pins the same bytes.
//
//	dragpass.mls.leaf|1|<account_id>|<device_id>|<signature_key_fingerprint>|<not_before_unix>|<reason>
func MLSLeafCanonical(accountID, deviceID, fingerprint string, notBefore int64, reason string) string {
	return strings.Join([]string{
		MLSLeafCanonicalDomain,
		strconv.Itoa(MLSLeafCanonicalVersion),
		accountID,
		deviceID,
		fingerprint,
		strconv.FormatInt(notBefore, 10),
		reason,
	}, "|")
}

// Validate checks structure only. Whether the key hashes to the fingerprint
// and the signature verifies is VerifyMLSLeafDeclaration's job.
func (d MLSLeafDeclaration) Validate() error {
	if err := requireMessageUUID(d.AccountID, "leaf_declaration.account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(d.DeviceID, "leaf_declaration.device_id"); err != nil {
		return err
	}
	if err := requireString(d.SignatureKey, "leaf_declaration.signature_key"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(d.SignatureKeyFingerprint, "leaf_declaration.signature_key_fingerprint"); err != nil {
		return err
	}
	if err := requireRotatedAt(d.NotBefore, "leaf_declaration.not_before"); err != nil {
		return err
	}
	if err := requireMLSLeafReason(d.Reason, "leaf_declaration.reason"); err != nil {
		return err
	}
	return requireString(d.Signature, "leaf_declaration.signature")
}

// MLSLeafDeclareRequest asks the Keeper to create (enroll) or replace (rotate)
// this device's leaf signature key and to sign a declaration for it.
//
// DeviceID is the Extension's X-Device-ID, the id the server already keys this
// device's refresh tokens and request-signing key by. The Keeper has no device
// identity of its own to offer instead.
type MLSLeafDeclareRequest struct {
	ChallengeToken   string `json:"challenge_token"`
	ServerSignature  string `json:"server_signature"`
	ServerKeyVersion uint   `json:"server_key_version,omitempty"`
	AccountID        string `json:"account_id"`
	DeviceID         string `json:"device_id"`
	NotBefore        int64  `json:"not_before"`
	Reason           string `json:"reason"`
}

func (r MLSLeafDeclareRequest) Validate() error {
	if err := requireString(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := requireString(r.ServerSignature, "server_signature"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.AccountID, "account_id"); err != nil {
		return err
	}
	if err := requireMessageUUID(r.DeviceID, "device_id"); err != nil {
		return err
	}
	if err := requireRotatedAt(r.NotBefore, "not_before"); err != nil {
		return err
	}
	return requireMLSLeafReason(r.Reason, "reason")
}

type MLSLeafDeclareResponseData struct {
	MLSLeafDeclaration
}

func requireMLSLeafReason(value, field string) error {
	switch value {
	case MLSLeafReasonEnroll, MLSLeafReasonRotate:
		return nil
	case "":
		return newValidationError(field, "must not be empty")
	default:
		return newValidationError(field, "must be enroll or rotate")
	}
}
