// key_rotation.go — the signed account key rotation statement (account key
// trust v1).
//
// A statement is how a key change explains itself to everyone who pinned the
// old key. It names both fingerprints and carries two RSA-PSS SHA-256
// signatures over the same canonical string: one by the key being left, one by
// the key being taken up. Together they say "the holder of both keys made this
// change", which is what lets a peer advance a pin instead of refusing the
// wrap.
//
// The type is shared by three surfaces — the two wrap requests consume chains
// of it, and the rotation and recovery responses produce single statements —
// so it lives in its own file rather than in whichever one needed it first.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §5, §6.2, §6.6.

package proto

import (
	"strconv"
	"strings"
)

const (
	// KeyRotationCanonicalDomain is the fourth member of the `dragpass.`
	// signing-domain family (after chat, chat.read, and message). The prefix is
	// what keeps a statement signature from verifying anywhere else.
	KeyRotationCanonicalDomain = "dragpass.keyrotation"

	// KeyRotationCanonicalVersion is the schema slot, always 1 in this version.
	KeyRotationCanonicalVersion = 1

	// The three reasons a key changed. `compromise` is the one that refuses
	// automatic succession: the holder is saying the old key is in someone
	// else's hands, so peers must re-check rather than follow the chain.
	// `recovery` is an ordinary RK24 recovery and is treated exactly like
	// `voluntary`.
	KeyRotationReasonVoluntary  = "voluntary"
	KeyRotationReasonRecovery   = "recovery"
	KeyRotationReasonCompromise = "compromise"

	// KeyRotationFingerprintHexLen — lowercase hex of a SHA-256.
	KeyRotationFingerprintHexLen = 64

	// KeyRotationMaxStatements caps one chain. A chain is the history between
	// a pin and the key in front of it; thirty-two rotations without a single
	// wrap in between is far past any real account.
	KeyRotationMaxStatements = 32

	// KeyRotationMaxRotatedAt is the largest integer a JSON number survives
	// intact on the other side of the bridge (2^53 - 1).
	KeyRotationMaxRotatedAt = 9007199254740991

	// KeyRotationPrepareMaxFutureSeconds is how far ahead of the Keeper's clock
	// a caller may date a statement it is asking to have signed. Covers
	// ordinary drift and nothing more.
	KeyRotationPrepareMaxFutureSeconds = 300
)

// KeyRotationStatement is one link of an account's key rotation chain. The two
// public keys are Base64-encoded PEM, matching the `accounts.public_key`
// column shape, so the fingerprints are recomputable from the statement alone
// after the account has already moved on.
type KeyRotationStatement struct {
	AccountID      string `json:"account_id"`
	OldFingerprint string `json:"old_fingerprint"`
	NewFingerprint string `json:"new_fingerprint"`
	RotatedAt      int64  `json:"rotated_at"`
	Reason         string `json:"reason"`
	OldPublicKey   string `json:"old_public_key"`
	NewPublicKey   string `json:"new_public_key"`
	OldSignature   string `json:"old_signature"`
	NewSignature   string `json:"new_signature"`
}

// Canonical renders the seven-item string both signatures cover.
func (s KeyRotationStatement) Canonical() string {
	return KeyRotationCanonical(s.AccountID, s.OldFingerprint, s.NewFingerprint, s.RotatedAt, s.Reason)
}

// KeyRotationCanonical builds the signing string from loose fields, for the
// side that is producing a statement and does not have one yet.
//
//	dragpass.keyrotation|1|<account_id>|<old_fp>|<new_fp>|<rotated_at>|<reason>
//
// Field order is fixed and both signatures cover the identical bytes.
func KeyRotationCanonical(accountID, oldFingerprint, newFingerprint string, rotatedAt int64, reason string) string {
	return strings.Join([]string{
		KeyRotationCanonicalDomain,
		strconv.Itoa(KeyRotationCanonicalVersion),
		accountID,
		oldFingerprint,
		newFingerprint,
		strconv.FormatInt(rotatedAt, 10),
		reason,
	}, "|")
}

// Validate checks the structure of a statement that arrived over the wire. It
// says nothing about whether the signatures verify or whether the chain links
// up — that is the Keeper's own check, deliberately separate, because a
// well-formed lie and a malformed request are different answers.
func (s KeyRotationStatement) Validate() error {
	if err := requireMessageUUID(s.AccountID, "rotation_statements.account_id"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(s.OldFingerprint, "rotation_statements.old_fingerprint"); err != nil {
		return err
	}
	if err := requireKeyFingerprint(s.NewFingerprint, "rotation_statements.new_fingerprint"); err != nil {
		return err
	}
	if err := requireRotatedAt(s.RotatedAt, "rotation_statements.rotated_at"); err != nil {
		return err
	}
	if err := requireKeyRotationReason(s.Reason, "rotation_statements.reason"); err != nil {
		return err
	}
	if err := requireString(s.OldPublicKey, "rotation_statements.old_public_key"); err != nil {
		return err
	}
	if err := requireString(s.NewPublicKey, "rotation_statements.new_public_key"); err != nil {
		return err
	}
	if err := requireString(s.OldSignature, "rotation_statements.old_signature"); err != nil {
		return err
	}
	return requireString(s.NewSignature, "rotation_statements.new_signature")
}

// ValidateKeyRotationStatements checks a whole chain's structure and its
// length. An absent chain is valid — it means "no rotation is claimed", which
// is the normal case and also the one the wrap path refuses when the key moved.
func ValidateKeyRotationStatements(statements []KeyRotationStatement) error {
	if len(statements) > KeyRotationMaxStatements {
		return newValidationError(
			"rotation_statements",
			"must hold at most "+strconv.Itoa(KeyRotationMaxStatements)+" statements",
		)
	}
	for _, statement := range statements {
		if err := statement.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// requireKeyFingerprint enforces the 64-character lowercase hex form. Uppercase
// is rejected rather than folded: two spellings of one fingerprint would
// compare unequal somewhere downstream.
func requireKeyFingerprint(value, field string) error {
	if value == "" {
		return newValidationError(field, "must not be empty")
	}
	if len(value) != KeyRotationFingerprintHexLen {
		return newValidationError(field, "must be 64 lowercase hex characters")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return newValidationError(field, "must be 64 lowercase hex characters")
	}
	return nil
}

// requireKeyRotationReason accepts the three values the chain verifier knows.
func requireKeyRotationReason(value, field string) error {
	switch value {
	case KeyRotationReasonVoluntary, KeyRotationReasonRecovery, KeyRotationReasonCompromise:
		return nil
	case "":
		return newValidationError(field, "must not be empty")
	default:
		return newValidationError(field, "must be voluntary, recovery, or compromise")
	}
}

// requireRotatedAt enforces a positive Unix-seconds value that survives the
// JSON number round trip.
func requireRotatedAt(value int64, field string) error {
	if value <= 0 || value > KeyRotationMaxRotatedAt {
		return newValidationError(field, "must be a positive Unix seconds value")
	}
	return nil
}

// requireOptionalAccountUUID allows an absent id and enforces the UUID form on
// anything else. Several fields in this model are optional only because they
// are the switch that turns pin enforcement on.
func requireOptionalAccountUUID(value, field string) error {
	if value == "" {
		return nil
	}
	return requireMessageUUID(value, field)
}
