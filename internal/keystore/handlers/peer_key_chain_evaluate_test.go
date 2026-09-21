// peer_key_chain_evaluate_test.go — the wrap-free evaluation action.
//
// Two things are being held down here. First, that a legitimate signed
// rotation can move a pin without a wrap, which is the deadlock the action
// exists to break. Second, that it is the *same* judgement the wrap path
// makes: TestPeerKeyChainEvaluate_AgreesWithTheWrapPath runs both against the
// same inputs on two identical devices and compares the verdict and the
// stored record.

package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func evaluateData(t *testing.T, resp proto.BaseResponse) proto.PeerKeyChainEvaluateResponseData {
	t.Helper()
	if !resp.Success {
		t.Fatalf("evaluate failed: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data, ok := resp.Data.(proto.PeerKeyChainEvaluateResponseData)
	if !ok {
		t.Fatalf("response data = %T, want PeerKeyChainEvaluateResponseData", resp.Data)
	}
	return data
}

// pinPeerTOFU puts a first-observation pin in place the way a wrap would.
func pinPeerTOFU(t *testing.T, fixture wrapFixture, key trustKey) {
	t.Helper()
	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  key.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("seeding wrap failed: %s", resp.Error)
	}
}

// ─── the deadlock this action breaks ────────────────────────────────────

// A peer rotates and signs it. Without a wrap in hand, the evaluation carries
// the pin to the new key and reports `rotated`.
func TestHandlePeerKeyChainEvaluate_ValidChainAdvancesThePin(t *testing.T) {
	fixture := newWrapFixture(t)
	old, next := newTrustKey(t), newTrustKey(t)
	pinPeerTOFU(t, fixture, old)

	data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      next.pair.PublicKey,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	}))

	if data.State != string(keychain.PeerKeyPinStateRotated) {
		t.Fatalf("state = %q, want rotated", data.State)
	}
	if data.Fingerprint != next.fingerprint {
		t.Fatalf("fingerprint = %q, want the one Keeper computes from the PEM", data.Fingerprint)
	}
	if !data.Advanced {
		t.Fatal("advanced=false on a chain that moved the pin")
	}
	if data.PinnedFingerprint != "" {
		t.Fatal("pinned_fingerprint rides along on `changed` only")
	}

	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if pin.Fingerprint != next.fingerprint || pin.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("pin = %+v, want a rotated pin on the new key", pin)
	}
	if pin.LastRotationFingerprint != old.fingerprint {
		t.Fatalf("last_rotation_fingerprint = %q, want the key the chain left", pin.LastRotationFingerprint)
	}
	if pin.VerifiedAt != 0 {
		t.Fatal("verified_at survived a rotation")
	}
}

// A `verified` pin does not stay verified across a rotation here either: a
// human compared the previous key, not this one.
func TestHandlePeerKeyChainEvaluate_RotationDropsVerified(t *testing.T) {
	fixture := newWrapFixture(t)
	old, next := newTrustKey(t), newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: old.fingerprint, PublicKey: old.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}

	data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      next.pair.PublicKey,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	}))

	if data.State != string(keychain.PeerKeyPinStateRotated) || !data.Advanced {
		t.Fatalf("state=%q advanced=%t, want an advancing rotation", data.State, data.Advanced)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.VerifiedAt != 0 {
		t.Fatalf("verified_at = %d, want it cleared", pin.VerifiedAt)
	}
}

// After the evaluation the wrap the SPA was blocking goes through, which is
// the whole reason the action exists.
func TestHandlePeerKeyChainEvaluate_UnblocksTheWrap(t *testing.T) {
	fixture := newWrapFixture(t)
	old, next := newTrustKey(t), newTrustKey(t)
	pinPeerTOFU(t, fixture, old)

	// With no chain the wrap is refused, which is the state the org is stuck in.
	blocked := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  next.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if blocked.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
		t.Fatalf("error_code = %q, want peer_key_changed", blocked.ErrorCode)
	}

	evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      next.pair.PublicKey,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	}))

	after := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  next.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !after.Success {
		t.Fatalf("the wrap is still blocked after the evaluation: %s (%s)", after.Error, after.ErrorCode)
	}
	if state := after.Data.(proto.DEKRewrapForMemberResponseData).PinState; state != string(keychain.PeerKeyPinStateRotated) {
		t.Fatalf("pin_state = %q, want rotated", state)
	}
}

// ─── the other three verdicts ───────────────────────────────────────────

func TestHandlePeerKeyChainEvaluate_FirstObservationPins(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: peer.pair.PublicKey,
	}))

	if data.State != string(keychain.PeerKeyPinStateTOFU) || !data.Advanced {
		t.Fatalf("state=%q advanced=%t, want a recorded first observation", data.State, data.Advanced)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.Fingerprint != peer.fingerprint {
		t.Fatalf("pin = %+v, want the observed key", pin)
	}
}

// Re-observing the pinned key reports the state it already had and says the
// pin did not move.
func TestHandlePeerKeyChainEvaluate_UnchangedKeyDoesNotAdvance(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: peer.fingerprint, PublicKey: peer.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}

	data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: peer.pair.PublicKey,
	}))

	if data.State != string(keychain.PeerKeyPinStateVerified) {
		t.Fatalf("state = %q, want verified to survive", data.State)
	}
	if data.Advanced {
		t.Fatal("advanced=true on a key that was already pinned")
	}
}

// Every way a chain can fail to explain a change lands on `changed`, carries
// both fingerprints, and leaves the record exactly as it was.
func TestHandlePeerKeyChainEvaluate_RefusesAndChangesNothing(t *testing.T) {
	old, next, stranger := newTrustKey(t), newTrustKey(t), newTrustKey(t)
	valid := statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary)

	forged := valid
	forged.NewSignature = valid.OldSignature // signed by the wrong key

	cases := []struct {
		name  string
		chain []proto.KeyRotationStatement
	}{
		{"no chain at all", nil},
		{
			"compromise chain",
			[]proto.KeyRotationStatement{statementFor(t, old, next, pinPeer, proto.KeyRotationReasonCompromise)},
		},
		{
			"broken chain",
			[]proto.KeyRotationStatement{statementFor(t, stranger, next, pinPeer, proto.KeyRotationReasonVoluntary)},
		},
		{"forged signature", []proto.KeyRotationStatement{forged}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fixture := newWrapFixture(t)
			pinPeerTOFU(t, fixture, old)
			before := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)

			data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
				OwnerAccountID:     pinOwnerA,
				AccountID:          pinPeer,
				PublicKey:          next.pair.PublicKey,
				RotationStatements: c.chain,
			}))

			if data.State != string(keychain.PeerKeyPinStateChanged) {
				t.Fatalf("state = %q, want changed", data.State)
			}
			if data.Advanced {
				t.Fatal("advanced=true on a refusal")
			}
			if data.Fingerprint != next.fingerprint || data.PinnedFingerprint != old.fingerprint {
				t.Fatalf("fingerprints = observed %q / pinned %q, want %q / %q",
					data.Fingerprint, data.PinnedFingerprint, next.fingerprint, old.fingerprint)
			}
			if after := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); after != before {
				t.Fatalf("pin moved on a refusal: %+v, want %+v", after, before)
			}
		})
	}
}

// ─── the same judgement as the wrap ─────────────────────────────────────

// Two identical devices, the same inputs: one evaluates, one wraps. The
// verdict and the stored record have to match, or there are two state
// machines where the contract says there is one.
func TestPeerKeyChainEvaluate_AgreesWithTheWrapPath(t *testing.T) {
	old, next, stranger := newTrustKey(t), newTrustKey(t), newTrustKey(t)

	cases := []struct {
		name      string
		observed  trustKey
		chain     []proto.KeyRotationStatement
		wantState keychain.PeerKeyPinState
	}{
		{"unchanged key", old, nil, keychain.PeerKeyPinStateTOFU},
		{
			"valid chain",
			next,
			[]proto.KeyRotationStatement{statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary)},
			keychain.PeerKeyPinStateRotated,
		},
		{"unexplained change", stranger, nil, keychain.PeerKeyPinStateChanged},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evaluated, wrapped := newWrapFixture(t), newWrapFixture(t)
			pinPeerTOFU(t, evaluated, old)
			pinPeerTOFU(t, wrapped, old)

			evalData := evaluateData(t, HandlePeerKeyChainEvaluate(evaluated.deps, proto.PeerKeyChainEvaluateRequest{
				OwnerAccountID:     pinOwnerA,
				AccountID:          pinPeer,
				PublicKey:          c.observed.pair.PublicKey,
				RotationStatements: c.chain,
			}))
			wrapResp := HandleDEKRewrapForMember(wrapped.deps, proto.DEKRewrapForMemberRequest{
				WrappedForMeB64:    wrapped.wrapped,
				OtherPublicKey:     c.observed.pair.PublicKey,
				OwnerAccountID:     pinOwnerA,
				OtherAccountID:     pinPeer,
				RotationStatements: c.chain,
			})

			if evalData.State != string(c.wantState) {
				t.Fatalf("evaluate state = %q, want %q", evalData.State, c.wantState)
			}

			if c.wantState == keychain.PeerKeyPinStateChanged {
				if wrapResp.Success || wrapResp.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
					t.Fatalf("wrap gave success=%t code=%q, want peer_key_changed",
						wrapResp.Success, wrapResp.ErrorCode)
				}
				changed := wrapResp.Data.(proto.PeerKeyChangedResponseData)
				if changed.ObservedFingerprint != evalData.Fingerprint ||
					changed.PinnedFingerprint != evalData.PinnedFingerprint {
					t.Fatalf("wrap reported %+v, evaluate reported observed %q / pinned %q",
						changed, evalData.Fingerprint, evalData.PinnedFingerprint)
				}
			} else {
				if !wrapResp.Success {
					t.Fatalf("wrap failed: %s (%s)", wrapResp.Error, wrapResp.ErrorCode)
				}
				if state := wrapResp.Data.(proto.DEKRewrapForMemberResponseData).PinState; state != evalData.State {
					t.Fatalf("wrap pin_state = %q, evaluate state = %q", state, evalData.State)
				}
			}

			// The record each device ends up with, compared field by field.
			// LastSeenAt is the one value a real clock could separate, so it
			// is normalized rather than trusted.
			fromEvaluate := mustGetPin(t, evaluated.deps, pinOwnerA, pinPeer)
			fromWrap := mustGetPin(t, wrapped.deps, pinOwnerA, pinPeer)
			fromEvaluate.FirstSeenAt, fromWrap.FirstSeenAt = 0, 0
			fromEvaluate.LastSeenAt, fromWrap.LastSeenAt = 0, 0
			if fromEvaluate != fromWrap {
				t.Fatalf("stored pins differ: evaluate %+v, wrap %+v", fromEvaluate, fromWrap)
			}
		})
	}
}

// ─── strict mode ────────────────────────────────────────────────────────

// Strict mode is a rule about wrapping, and this action wraps nothing, so it
// reports the true state instead of `peer_key_unverified`. Refusing here would
// make the deadlock worse: a strict device could never learn that a rotation
// chain was valid, and would be left with the two wrong escapes — verify,
// which erases the rotation signal, and forget, which drops the protection.
func TestHandlePeerKeyChainEvaluate_StrictModeStillReportsTheState(t *testing.T) {
	fixture := newWrapFixture(t)
	old, next := newTrustKey(t), newTrustKey(t)
	pinPeerTOFU(t, fixture, old)
	setStrictMode(t, fixture.deps, true)

	data := evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      next.pair.PublicKey,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	}))

	if data.State != string(keychain.PeerKeyPinStateRotated) || !data.Advanced {
		t.Fatalf("state=%q advanced=%t under strict mode, want the true rotation verdict",
			data.State, data.Advanced)
	}
}

// And the enforcement point does not move: a pin this action advanced still
// refuses the wrap under strict mode until a human verifies it, so reporting
// the true state hands out no wrap strict mode would have refused.
func TestHandlePeerKeyChainEvaluate_StrictModeStillRefusesTheWrap(t *testing.T) {
	fixture := newWrapFixture(t)
	old, next := newTrustKey(t), newTrustKey(t)
	pinPeerTOFU(t, fixture, old)
	setStrictMode(t, fixture.deps, true)

	evaluateData(t, HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      next.pair.PublicKey,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, old, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	}))

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  next.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if resp.Success {
		t.Fatal("a rotated pin wrapped under strict mode")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
		t.Fatalf("error_code = %q, want peer_key_unverified", resp.ErrorCode)
	}
}

// ─── validation ─────────────────────────────────────────────────────────

func TestPeerKeyChainEvaluate_Validate(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	peer := newTrustKey(t)

	cases := []struct {
		name string
		req  proto.PeerKeyChainEvaluateRequest
	}{
		{"no owner", proto.PeerKeyChainEvaluateRequest{
			AccountID: pinPeer, PublicKey: peer.pair.PublicKey,
		}},
		{"no account", proto.PeerKeyChainEvaluateRequest{
			OwnerAccountID: pinOwnerA, PublicKey: peer.pair.PublicKey,
		}},
		{"nil uuid", proto.PeerKeyChainEvaluateRequest{
			OwnerAccountID: pinOwnerA,
			AccountID:      "00000000-0000-0000-0000-000000000000",
			PublicKey:      peer.pair.PublicKey,
		}},
		{"not a PEM", proto.PeerKeyChainEvaluateRequest{
			OwnerAccountID: pinOwnerA, AccountID: pinPeer, PublicKey: "not-a-pem",
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := HandlePeerKeyChainEvaluate(deps, c.req)
			if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
				t.Fatalf("success=%t code=%q, want validation_error", resp.Success, resp.ErrorCode)
			}
		})
	}
}

// A PEM header wrapped around something that is not a key fails as a bad key
// rather than settling as a fingerprint.
func TestHandlePeerKeyChainEvaluate_RejectsAnUnparseableKey(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandlePeerKeyChainEvaluate(deps, proto.PeerKeyChainEvaluateRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		PublicKey:      "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----",
	})
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeValidation) {
		t.Fatalf("success=%t code=%q, want validation_error", resp.Success, resp.ErrorCode)
	}
	if _, err := keychain.GetPeerKeyPin(deps.Store, pinOwnerA, pinPeer); err == nil {
		t.Fatal("an unparseable key was pinned")
	}
}
