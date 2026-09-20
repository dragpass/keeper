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
	// Reason explains a refusal in one English sentence. Empty when allowed.
	// It names conditions, never values: no fingerprint, key, or signature
	// goes into it, because it travels into an error message and a log line.
	Reason string
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
			Allowed: false,
			State:   keychain.PeerKeyPinStateChanged,
			Reason:  err.Error(),
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
