// peer_key_trust.go — the D3 state machine and the rotation chain verifier
// (account key trust v1).
//
// evaluatePeerKeyTrust is a pure function of (stored pin, observed
// fingerprint, claimed rotation chain, clock). It reads nothing and writes
// nothing, so every branch is reachable from a table test and the wrap path
// cannot accidentally decide something the tests do not cover.
//
// The shape of the decision:
//
//	no pin                  → tofu, allow, remember the observation
//	pin matches what we see → keep the state, allow, touch last_seen_at
//	pin differs, chain ok   → rotated, allow, move the pin forward
//	pin differs, otherwise  → changed, refuse, leave the pin exactly as it is
//
// The last line is the one that matters. A refusal never mutates the pin and
// never produces wrap output, so a server that swaps a member's key cannot get
// a Group DEK wrapped to it and cannot quietly launder the swap into the
// record by retrying. Only a human calling peer_key_pin_verify moves a pin
// across a change the chain does not explain.
//
// applyPeerKeyPolicy is the device's own setting layered on top of that
// decision: with strict mode on, an allowed outcome that is not `verified` is
// refused too. It is a separate step so the state machine keeps deciding what
// the key is, and the policy only decides how much the device insists on
// before wrapping to it.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.2.

package handlers

import (
	"encoding/base64"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// peerKeyTrustOutcome is what the state machine decided.
type peerKeyTrustOutcome struct {
	// Allowed reports whether the wrap may proceed.
	Allowed bool
	// State is what the caller reports back: the pin's state when allowed,
	// `changed` when not.
	State keychain.PeerKeyPinState
	// Pin is the record to persist. Meaningful only when Allowed — a refusal
	// leaves the stored pin untouched.
	Pin keychain.PeerKeyPin
	// Unverified marks a refusal that the device policy produced rather than
	// the state machine: the key is the one we expected, nobody has compared
	// it out of band, and strict mode is on. The caller turns it into
	// `peer_key_unverified` instead of `peer_key_changed`, because what the
	// user has to do about it is different — finish the check, rather than
	// work out which of two keys is real.
	Unverified bool
	// Reason explains a refusal in one English sentence. Empty when allowed.
	// It names conditions, never values: no fingerprint, key, or signature
	// goes into it, because it travels into an error message and a log line.
	Reason string
	// PinnedFingerprint is what the pin held when a refusal was decided, so
	// the caller can show it next to the observed one. Empty when allowed and
	// when there was no pin to begin with.
	PinnedFingerprint string
}

// evaluatePeerKeyTrust runs the state machine. `now` is Unix seconds.
func evaluatePeerKeyTrust(
	existing *keychain.PeerKeyPin,
	peerAccountID string,
	observed string,
	statements []proto.KeyRotationStatement,
	now int64,
) peerKeyTrustOutcome {
	// 1. Never seen this peer. Trust on first use, and record it.
	if existing == nil {
		return peerKeyTrustOutcome{
			Allowed: true,
			State:   keychain.PeerKeyPinStateTOFU,
			Pin: keychain.PeerKeyPin{
				V:           keychain.PeerKeyPinVersion,
				Fingerprint: observed,
				State:       keychain.PeerKeyPinStateTOFU,
				FirstSeenAt: now,
				LastSeenAt:  now,
			},
		}
	}

	// 2. Same key as last time. Nothing about the trust level changes.
	if existing.Fingerprint == observed {
		pin := *existing
		pin.LastSeenAt = now
		return peerKeyTrustOutcome{Allowed: true, State: pin.State, Pin: pin}
	}

	// 3. A different key. The only thing that can explain it is a chain of
	//    statements running from the pinned fingerprint to this one.
	if err := verifyRotationChain(statements, peerAccountID, existing.Fingerprint, observed); err != nil {
		return peerKeyTrustOutcome{
			Allowed:           false,
			State:             keychain.PeerKeyPinStateChanged,
			Reason:            err.Error(),
			PinnedFingerprint: existing.Fingerprint,
		}
	}

	// The chain holds. The pin moves forward and drops to `rotated` — a key
	// a human once compared is not the key in front of us any more, so
	// `verified` does not survive, and the UI has a reason to ask again.
	pin := *existing
	pin.Fingerprint = observed
	pin.State = keychain.PeerKeyPinStateRotated
	pin.LastRotationFingerprint = existing.Fingerprint
	pin.VerifiedAt = 0
	pin.LastSeenAt = now
	return peerKeyTrustOutcome{Allowed: true, State: keychain.PeerKeyPinStateRotated, Pin: pin}
}

// applyPeerKeyPolicy narrows an allowed outcome when the device is in strict
// mode (§6.5). Off — the default — it changes nothing.
//
// It runs after the state machine rather than inside it, which is what keeps
// `changed` short-circuiting first: a refusal arrives here already refused and
// leaves untouched, so a substituted key is still reported as `peer_key_changed`
// and strict mode never renames it into a milder-sounding policy refusal.
//
// On, the rule is the whole of the setting: anything the user has not compared
// out of band is refused. That covers a first observation (`tofu` with no pin
// yet), an earlier observation nobody got around to checking (`tofu`), and a
// peer whose rotation chain verified but whose current key no human has read
// aloud (`rotated`). Letting the first observation through would be the worst
// of the three to skip, since that is the wrap that actually hands the Group
// DEK to a key nobody has looked at.
//
// A policy refusal leaves the pin alone for the same reason a `changed` one
// does: nothing was wrapped, so nothing should be recorded as having been.
func applyPeerKeyPolicy(outcome peerKeyTrustOutcome, requireVerifiedPeers bool) peerKeyTrustOutcome {
	if !outcome.Allowed || !requireVerifiedPeers {
		return outcome
	}
	if outcome.State == keychain.PeerKeyPinStateVerified {
		return outcome
	}
	return peerKeyTrustOutcome{
		Allowed:    false,
		State:      outcome.State,
		Unverified: true,
		Reason:     "peer key has not been verified out of band and this device requires verified peers",
	}
}

// verifyRotationChain decides whether `statements` genuinely carries the
// account from the pinned fingerprint to the observed one.
//
// Every failure here is the same verdict, `changed`, and the returned error
// only says which condition failed. That is deliberate: distinguishing "your
// signature is bad" from "your chain is short" for a caller who is assumed to
// be the attacker buys nothing, and the refusal is identical either way.
func verifyRotationChain(statements []proto.KeyRotationStatement, accountID, from, to string) error {
	if len(statements) == 0 {
		return errors.New("peer account key changed and no rotation chain was supplied")
	}
	if statements[0].OldFingerprint != from {
		return errors.New("rotation chain does not start at the pinned fingerprint")
	}
	if statements[len(statements)-1].NewFingerprint != to {
		return errors.New("rotation chain does not end at the observed key")
	}
	for i, statement := range statements {
		if i > 0 && statement.OldFingerprint != statements[i-1].NewFingerprint {
			return errors.New("rotation chain has a broken link")
		}
		if statement.AccountID != accountID {
			return errors.New("rotation statement names a different account")
		}
		// A compromise statement is the holder saying the old key is in
		// someone else's hands. Following it automatically would be following
		// a chain whose earlier links the attacker may control, so it always
		// lands on `changed` and a human re-checks. It is the only reason
		// that does this: `recovery` is an ordinary RK24 recovery and behaves
		// exactly like `voluntary`.
		if statement.Reason == proto.KeyRotationReasonCompromise {
			return errors.New("rotation chain contains a compromise statement")
		}
		if err := verifyRotationStatement(statement); err != nil {
			return err
		}
	}
	return nil
}

// verifyRotationStatement checks one link against itself: that the
// fingerprints are the ones its own public keys hash to, and that both
// signatures cover its canonical string.
//
// Recomputing the fingerprints is what keeps the chain honest. Without it a
// statement could name any two fingerprints it liked and sign a canonical
// built from them with two keys of its own, and the links would appear to
// connect while the keys underneath were never the account's.
func verifyRotationStatement(statement proto.KeyRotationStatement) error {
	oldPEM, err := base64.StdEncoding.DecodeString(statement.OldPublicKey)
	if err != nil {
		return errors.New("rotation statement old_public_key is not Base64")
	}
	newPEM, err := base64.StdEncoding.DecodeString(statement.NewPublicKey)
	if err != nil {
		return errors.New("rotation statement new_public_key is not Base64")
	}
	if crypto.AccountKeyFingerprint(oldPEM) != statement.OldFingerprint {
		return errors.New("rotation statement old_fingerprint does not match its old_public_key")
	}
	if crypto.AccountKeyFingerprint(newPEM) != statement.NewFingerprint {
		return errors.New("rotation statement new_fingerprint does not match its new_public_key")
	}

	canonical := statement.Canonical()
	if err := verifyStatementSignature(oldPEM, statement.OldSignature, canonical); err != nil {
		return errors.New("rotation statement old_signature does not verify")
	}
	if err := verifyStatementSignature(newPEM, statement.NewSignature, canonical); err != nil {
		return errors.New("rotation statement new_signature does not verify")
	}
	return nil
}

func verifyStatementSignature(publicKeyPEM []byte, signatureB64, canonical string) error {
	publicKey, err := crypto.ParsePublicKey(string(publicKeyPEM))
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return err
	}
	return crypto.VerifySignature(publicKey, canonical, signature)
}
