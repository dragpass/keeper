// peer_key_chain_evaluate.go — judging a peer's key without wrapping to it
// (account key trust v1).
//
// Why this exists. The pin only advanced to `rotated` inside a wrap, and the
// SPA blocks all four wrap entry points — invite, DEK rotation, retained
// backfill, DM open — while the pinned fingerprint differs from the key the
// server is serving. A peer who rotated legitimately therefore locked the org:
// the signed chain that explains the change existed, and there was no call
// that could put it in front of the Keeper. The blocked banner offered two
// ways out and both were wrong. Out-of-band verify asks a human to redo work
// a signature already did, lands on `verified` instead of `rotated`, and drops
// last_rotation_fingerprint, erasing the "this key changed" signal — and the
// same button launders a genuine substitution just as readily. Forget deletes
// the pin so the next wrap is TOFU, which is throwing the protection away.
//
// So the fix is a call that judges without wrapping. It takes the same inputs
// the wrap path takes, runs the same evaluatePeerKeyTrust, and persists the
// same record. There is no second state machine here and there must not be
// one: the point of the action is that the wrap's answer and this answer are
// the same answer.
//
// It does not widen what a local caller can do. Anyone who can reach the
// Keeper's stdio loop can already call dek_rewrap_for_member with exactly
// these fields, which runs this same evaluation before it produces anything.
// What this removes is the need to hold a wrapped Group DEK in order to ask
// the question — not a check.
//
// Strict mode deliberately does not apply here; the reasoning is on the
// applyPeerKeyPolicy call site below.
//
// Contract: dragpass-control-plane
// docs/exec-plans/active/account-key-trust-implementation.md §6.2, §6.4, §6.5.

package handlers

import (
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// HandlePeerKeyChainEvaluate runs the trust state machine for one peer and
// reports the verdict.
func HandlePeerKeyChainEvaluate(d Deps, req proto.PeerKeyChainEvaluateRequest) proto.BaseResponse {
	d.Logger.Println("peer key chain evaluate request processing...")

	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}

	if resp, ok := requirePeerKeyOwner(d, req.OwnerAccountID); !ok {
		return resp
	}

	// Parse before hashing, the way peer_key_pin_verify does: a string that
	// opens with a PEM header but holds no key must fail as a bad key rather
	// than settle as a fingerprint.
	if _, err := crypto.ParsePublicKey(req.PublicKey); err != nil {
		d.Logger.Printf("peer key chain evaluate error: failed to parse public key: %v", err)
		return errs.CodeResponse(errs.ErrCodeValidation, "failed to parse public key: "+err.Error())
	}
	// Hashed over the PEM exactly as it arrived, not over a re-serialization
	// of the parsed key — the same bytes the wrap path hashes, so the two
	// cannot drift.
	observed := crypto.AccountKeyFingerprint([]byte(req.PublicKey))

	existing, err := loadPeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID)
	if err != nil {
		d.Logger.Printf("peer key chain evaluate error: failed to read pin: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to read peer key pin: "+err.Error())
	}

	// The same call the wrap path makes, with the same arguments.
	//
	// applyPeerKeyPolicy is deliberately absent. Strict mode's rule is "do
	// not wrap to a key nobody compared out of band", and this action wraps
	// nothing, so it has no output to withhold. Applying it here would also
	// make the deadlock this action exists to break strictly worse: a strict
	// device could never learn that a rotation chain was valid, and would be
	// left with exactly the two wrong escapes above. The enforcement point
	// stays where §6.5 put it — a pin this action moves to `rotated` still
	// refuses the next wrap with `peer_key_unverified` until a human verifies
	// it, so reporting the true state hands out no wrap strict mode would
	// have refused. It only lets the UI ask for that verification against the
	// right key.
	outcome := evaluatePeerKeyTrust(existing, req.AccountID, observed, req.RotationStatements, d.Now().Unix())

	if !outcome.Allowed {
		d.Logger.Printf("peer key chain evaluate: no chain explains the key change: %s", outcome.Reason)
		return proto.BaseResponse{Success: true, Data: proto.PeerKeyChainEvaluateResponseData{
			State:             string(keychain.PeerKeyPinStateChanged),
			Fingerprint:       observed,
			Advanced:          false,
			PinnedFingerprint: outcome.PinnedFingerprint,
		}}
	}

	// "Moved" means the record now points at a different key than it did:
	// a pin created where there was none, or one a valid chain carried
	// forward. Re-observing the pinned key only touches last_seen_at.
	advanced := existing == nil || existing.Fingerprint != outcome.Pin.Fingerprint

	if err := keychain.SavePeerKeyPin(d.Store, req.OwnerAccountID, req.AccountID, outcome.Pin); err != nil {
		d.Logger.Printf("peer key chain evaluate error: failed to save pin: %v", err)
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "failed to save peer key pin: "+err.Error())
	}

	d.Logger.Printf("peer key chain evaluate successful (state=%s, advanced=%t)", outcome.State, advanced)
	return proto.BaseResponse{Success: true, Data: proto.PeerKeyChainEvaluateResponseData{
		State:       string(outcome.State),
		Fingerprint: observed,
		Advanced:    advanced,
	}}
}
