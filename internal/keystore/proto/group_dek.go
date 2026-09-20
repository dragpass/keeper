// group_dek_models.go — Group DEK RSA wrap/unwrap + Recovery composites +
// admin raw-free composite action payloads.

package proto

// DEKRewrapWithOldKeyRequest is the request for the Recovery composite
// re-wrap action. Replaces the old `unwrapgroupdekwithkey` + wrap pair with
// a single Keeper-side composite action so the raw Group DEK does not live
// in the Extension JS heap.
//
// Takes a `recovery_handle` instead of the PEM. The PEM is referenced
// through the handle from the store pre-registered by recovery_session_open.
//
// NewPublicKey is the new RSA public key PEM of the re-wrap target member
// (usually self).
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
//
// The three account key trust fields are optional, and optional is a
// compatibility device rather than a hole. What the pin defends against is a
// malicious server, not a malicious Extension: an Extension already under an
// attacker's control has easier routes than omitting an id. This version of
// the Extension sends the ids from all four of its wrap call sites, and the
// SPA never assembles a Keeper request at all, so a `pin_enforced:false`
// response is a regression signal worth a console warning rather than a
// supported mode.
type DEKRewrapForMemberRequest struct {
	WrappedForMeB64 string `json:"wrapped_for_me_b64"`
	OtherPublicKey  string `json:"other_public_key"`
	// OwnerAccountID scopes the pin. Pins belong to the account doing the
	// wrapping, so two accounts sharing a device keep separate trust records.
	OwnerAccountID string `json:"owner_account_id,omitempty"`
	// OtherAccountID names the peer being wrapped to. Its presence is what
	// turns pin enforcement on.
	OtherAccountID string `json:"other_account_id,omitempty"`
	// RotationStatements is the chain that explains a key change, fetched
	// from the server only when the pin and the served key already disagree.
	// Absent means no rotation is claimed.
	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

func (r DEKRewrapForMemberRequest) Validate() error {
	if _, err := requireBase64(r.WrappedForMeB64, "wrapped_for_me_b64"); err != nil {
		return err
	}
	if err := requirePEM(r.OtherPublicKey, "other_public_key"); err != nil {
		return err
	}
	if err := requireOptionalAccountUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	if err := requireOptionalAccountUUID(r.OtherAccountID, "other_account_id"); err != nil {
		return err
	}
	// The two ids travel together or not at all. A peer id without an owner
	// has no pin set to live in, and an owner without a peer is enforcement
	// the caller asked for and then gave nothing to enforce against.
	if (r.OwnerAccountID == "") != (r.OtherAccountID == "") {
		return newValidationError(
			"owner_account_id",
			"must be sent together with other_account_id",
		)
	}
	return ValidateKeyRotationStatements(r.RotationStatements)
}

type DEKRewrapForMemberResponseData struct {
	EncryptedForOtherB64 string `json:"encrypted_for_other_b64"`
	// PinEnforced is false when the request named no account, so the caller
	// can tell "the pin passed" from "no pin was consulted".
	PinEnforced bool `json:"pin_enforced"`
	// PinState is the peer's trust level after the wrap: tofu, verified, or
	// rotated. Absent when nothing was enforced. A refused wrap has no
	// response at all — `changed` arrives as peer_key_changed.
	PinState string `json:"pin_state,omitempty"`
}

// DEKUnwrapAndRewrapForManyRequest — the multi-recipient variant of
// DEKRewrapForMemberRequest. Unwraps my wrapped Group DEK once with the
// Keychain private key and re-wraps it to every recipient public key. The
// raw Group DEK is unwrapped a single time and lives only briefly in Keeper
// memory; the response carries only the parallel list of new wraps.
//
// Usage: adminRotateDek — wrap the OLD Group DEK to each active member plus
// the org archive key in one round-trip, replacing the per-member
// unwrap→JS→wrap loop so the raw never enters the Extension JS heap.
//
// Two request shapes, exactly one per call. `recipients` is the shape that
// carries account ids and therefore gets pin enforcement;
// `recipient_public_keys` is the original flat list, still accepted and still
// unenforced. Sending both is refused rather than resolved, because a caller
// that populated both has a bug and picking one for it would hide which.
type DEKUnwrapAndRewrapForManyRequest struct {
	WrappedForMeB64 string `json:"wrapped_for_me_b64"`
	// Recipients is the enforced path. A recipient with no account_id is
	// pin-exempt — the org archive key is a resource, not an account.
	Recipients []DEKRewrapRecipient `json:"recipients,omitempty"`
	// RecipientPublicKeys is the pre-0.0.31 path. Kept working, never
	// enforced.
	RecipientPublicKeys []string `json:"recipient_public_keys,omitempty"`
	// OwnerAccountID scopes the pins. Required as soon as any recipient
	// names an account.
	OwnerAccountID string `json:"owner_account_id,omitempty"`
}

// DEKRewrapRecipient is one wrap target. PublicKey is the PEM the DEK is
// wrapped to; AccountID names whose key it is meant to be, which is what makes
// the claim checkable.
type DEKRewrapRecipient struct {
	AccountID          string                 `json:"account_id,omitempty"`
	PublicKey          string                 `json:"public_key"`
	RotationStatements []KeyRotationStatement `json:"rotation_statements,omitempty"`
}

// DEKRewrapMaxRecipients caps one call. The org member ceiling is 30, plus the
// archive key and room to spare.
const DEKRewrapMaxRecipients = 64

// DEKRewrapMaxRequestBytes caps the raw payload of both wrap actions. Enforced
// by the dispatcher before the request is decoded, so an oversized chain never
// reaches the point where a Group DEK would be unwrapped.
const DEKRewrapMaxRequestBytes = 512 * 1024

func (r DEKUnwrapAndRewrapForManyRequest) Validate() error {
	if _, err := requireBase64(r.WrappedForMeB64, "wrapped_for_me_b64"); err != nil {
		return err
	}
	if len(r.Recipients) > 0 && len(r.RecipientPublicKeys) > 0 {
		return newValidationError(
			"recipients",
			"must not be sent together with recipient_public_keys",
		)
	}
	if len(r.Recipients) == 0 && len(r.RecipientPublicKeys) == 0 {
		return newValidationError(
			"recipients",
			"must not be empty (or send the legacy recipient_public_keys)",
		)
	}
	if err := requireOptionalAccountUUID(r.OwnerAccountID, "owner_account_id"); err != nil {
		return err
	}
	if len(r.RecipientPublicKeys) > 0 {
		if len(r.RecipientPublicKeys) > DEKRewrapMaxRecipients {
			return newValidationError("recipient_public_keys", "must hold at most 64 recipients")
		}
		for _, pem := range r.RecipientPublicKeys {
			if err := requirePEM(pem, "recipient_public_keys"); err != nil {
				return err
			}
		}
		return nil
	}
	if len(r.Recipients) > DEKRewrapMaxRecipients {
		return newValidationError("recipients", "must hold at most 64 recipients")
	}
	// One account may not appear twice. The response lists run parallel to the
	// request, so a repeated id would report two pin states for one peer, and
	// the second evaluation would judge the first one's freshly written pin
	// instead of the one the call started from. Either the caller built the
	// list wrong or something upstream is trying to get two different keys
	// accepted for one account in a single pass.
	seenAccounts := make(map[string]struct{}, len(r.Recipients))
	for _, recipient := range r.Recipients {
		if recipient.AccountID == "" {
			continue
		}
		if _, dup := seenAccounts[recipient.AccountID]; dup {
			return newValidationError("recipients.account_id", "must not repeat an account")
		}
		seenAccounts[recipient.AccountID] = struct{}{}
	}
	for _, recipient := range r.Recipients {
		if err := requirePEM(recipient.PublicKey, "recipients.public_key"); err != nil {
			return err
		}
		if err := requireOptionalAccountUUID(recipient.AccountID, "recipients.account_id"); err != nil {
			return err
		}
		// A pin lives in an owner's set, so naming a peer without naming the
		// owner asks for a record with nowhere to go.
		if recipient.AccountID != "" && r.OwnerAccountID == "" {
			return newValidationError(
				"owner_account_id",
				"must be sent when a recipient names an account_id",
			)
		}
		if err := ValidateKeyRotationStatements(recipient.RotationStatements); err != nil {
			return err
		}
	}
	return nil
}

// RecipientList renders either request shape as the enforced one, so the
// handler has a single path. A legacy entry becomes a recipient with no
// account id, which is exactly how it is treated: wrapped, not pinned.
func (r DEKUnwrapAndRewrapForManyRequest) RecipientList() []DEKRewrapRecipient {
	if len(r.Recipients) > 0 {
		return r.Recipients
	}
	recipients := make([]DEKRewrapRecipient, len(r.RecipientPublicKeys))
	for i, pem := range r.RecipientPublicKeys {
		recipients[i] = DEKRewrapRecipient{PublicKey: pem}
	}
	return recipients
}

// DEKUnwrapAndRewrapForManyResponseData carries the new wraps in the same
// order as the request's recipients — the caller maps each entry back to its
// recipient by index.
type DEKUnwrapAndRewrapForManyResponseData struct {
	EncryptedForRecipientsB64 []string `json:"encrypted_for_recipients_b64"`
	// PinEnforced is true when at least one recipient named an account and
	// was therefore checked.
	PinEnforced bool `json:"pin_enforced"`
	// PinStates runs parallel to the wraps: tofu, verified, rotated, or
	// exempt for a recipient that named no account. Absent when nothing was
	// enforced.
	PinStates []string `json:"pin_states,omitempty"`
}
