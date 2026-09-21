// peer_key_policy_test.go — the strict-mode toggle and what it does to the
// wrap path (account key trust v1, §6.5).
//
// The two policy actions run against MemorySecretStore through the real
// keychain helpers, so a value written by peer_key_policy_set is the value the
// enforcement path reads back.

package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// setStrictMode turns the device policy on or off through the action, not
// through the keychain helper, so the tests below exercise the surface the
// options page actually calls.
func setStrictMode(t *testing.T, deps Deps, require bool) {
	t.Helper()
	resp := HandlePeerKeyPolicySet(deps, proto.PeerKeyPolicySetRequest{RequireVerifiedPeers: &require})
	if !resp.Success {
		t.Fatalf("peer_key_policy_set(%t) failed: %s", require, resp.Error)
	}
	if data := resp.Data.(proto.PeerKeyPolicyResponseData); data.RequireVerifiedPeers != require {
		t.Fatalf("set reported require_verified_peers=%t, want %t", data.RequireVerifiedPeers, require)
	}
}

func readStrictMode(t *testing.T, deps Deps) bool {
	t.Helper()
	resp := HandlePeerKeyPolicyGet(deps, proto.PeerKeyPolicyGetRequest{})
	if !resp.Success {
		t.Fatalf("peer_key_policy_get failed: %s", resp.Error)
	}
	return resp.Data.(proto.PeerKeyPolicyResponseData).RequireVerifiedPeers
}

// ─── the policy actions ─────────────────────────────────────────────────

// A device that has never set a policy is not in strict mode. Absence is the
// shipped state, not a missing record.
func TestHandlePeerKeyPolicyGet_DefaultsOff(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	if readStrictMode(t, deps) {
		t.Fatal("a fresh device reported strict mode on")
	}
}

// Set then get, in both directions: turning it back off has to stick as
// firmly as turning it on.
func TestHandlePeerKeyPolicy_RoundTrips(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	setStrictMode(t, deps, true)
	if !readStrictMode(t, deps) {
		t.Fatal("strict mode did not survive the round trip")
	}

	setStrictMode(t, deps, false)
	if readStrictMode(t, deps) {
		t.Fatal("strict mode stayed on after being turned off")
	}
}

// A payload with no field is a caller bug rather than "turn it off". The
// pointer is what makes that distinction available at all.
func TestPeerKeyPolicySet_Validate_RequiresTheField(t *testing.T) {
	if err := (proto.PeerKeyPolicySetRequest{}).Validate(); err == nil {
		t.Fatal("expected a validation error for a missing require_verified_peers")
	}
}

// The policy is a property of the device, so it is stored under one name with
// no owner in it. Two accounts sharing a machine share the setting while
// keeping separate pins.
func TestPeerKeyPolicy_IsNotOwnerScoped(t *testing.T) {
	deps, _, store := newTestDeps(t)

	setStrictMode(t, deps, true)

	raw, err := store.Get(config.Service, config.PeerKeyPolicyAccount)
	if err != nil {
		t.Fatalf("policy is not at the device-wide account name: %v", err)
	}
	if strings.Contains(config.PeerKeyPolicyAccount, ":") {
		t.Fatalf("policy account name %q looks scoped", config.PeerKeyPolicyAccount)
	}
	var stored keychain.PeerKeyPolicy
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("stored policy is not readable JSON: %v", err)
	}
	if stored.V != keychain.PeerKeyPolicyVersion || !stored.RequireVerifiedPeers {
		t.Fatalf("stored policy = %+v, want a versioned record with strict mode on", stored)
	}
}

// ─── what strict mode does to the wrap path ─────────────────────────────

// Owner A turns strict mode on; owner B on the same device gets the same
// answer. Pins are per owner, the policy is per machine.
func TestEnforcePeerKeyPins_StrictAppliesToEveryOwner(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	setStrictMode(t, fixture.deps, true)

	for _, owner := range []string{pinOwnerA, pinOwnerB} {
		// Owner TOFU binds the device to the first id it sees, so the second
		// owner arrives the way a real one would: after an options-page reset.
		switchPeerKeyOwner(t, fixture.deps)
		resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: fixture.wrapped,
			OtherPublicKey:  peer.pair.PublicKey,
			OwnerAccountID:  owner,
			OtherAccountID:  pinPeer,
		})
		if resp.Success {
			t.Fatalf("owner %s wrapped to an unverified peer under strict mode", owner)
		}
		if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
			t.Fatalf("owner %s got error_code %q, want peer_key_unverified", owner, resp.ErrorCode)
		}
	}
}

// A peer nobody has ever observed is not a peer anybody compared, so strict
// mode refuses the wrap that would have created the pin. Skipping this one
// would be the worst of the three to skip: it is the wrap that actually hands
// the Group DEK to a key nobody looked at.
func TestHandleDEKRewrapForMember_StrictRefusesFirstObservation(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if resp.Success {
		t.Fatal("strict mode wrapped to a peer that had never been observed")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
		t.Fatalf("error_code = %q, want peer_key_unverified", resp.ErrorCode)
	}
	assertNoWrapOutput(t, resp, "encrypted_for_other_b64")
	// A policy refusal records nothing, the same way a `changed` refusal does.
	if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerA, pinPeer); err == nil {
		t.Fatal("a refused wrap left a pin behind")
	}
}

// An existing `tofu` pin is the same answer: the key has not changed, but
// nobody has checked it.
func TestHandleDEKRewrapForMember_StrictRefusesTOFUPin(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("seed wrap failed: %s", resp.Error)
	}

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if resp.Success {
		t.Fatal("strict mode wrapped to a tofu peer")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
		t.Fatalf("error_code = %q, want peer_key_unverified", resp.ErrorCode)
	}
	assertNoWrapOutput(t, resp, "encrypted_for_other_b64")
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.State != keychain.PeerKeyPinStateTOFU {
		t.Fatalf("pin state = %q, want the record left at tofu", pin.State)
	}
}

// A chain that verifies proves the account rotated its key. It does not prove
// anybody read the new fingerprint aloud, so `rotated` is refused too and the
// pin does not advance.
func TestHandleDEKRewrapForMember_StrictRefusesRotated(t *testing.T) {
	fixture := newWrapFixture(t)
	original, next := newTrustKey(t), newTrustKey(t)

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  original.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("seed wrap failed: %s", resp.Error)
	}

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  next.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, original, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	})
	if resp.Success {
		t.Fatal("strict mode wrapped to a rotated peer")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
		t.Fatalf("error_code = %q, want peer_key_unverified", resp.ErrorCode)
	}
	assertNoWrapOutput(t, resp, "encrypted_for_other_b64")
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.Fingerprint != original.fingerprint {
		t.Fatalf("pin advanced to %q on a refused wrap", pin.Fingerprint)
	}
}

// The one state strict mode lets through.
func TestHandleDEKRewrapForMember_StrictAllowsVerified(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		Fingerprint:    peer.fingerprint,
		PublicKey:      peer.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !resp.Success {
		t.Fatalf("strict mode refused a verified peer: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data := resp.Data.(proto.DEKRewrapForMemberResponseData)
	if data.PinState != string(keychain.PeerKeyPinStateVerified) {
		t.Fatalf("pin_state = %q, want verified", data.PinState)
	}
	if data.EncryptedForOtherB64 == "" {
		t.Fatal("no wrap produced for a verified peer")
	}
}

// `changed` is the state machine's verdict, not the policy's, so it keeps its
// own code and its two fingerprints whichever way the toggle is set. Strict
// mode must not rename a detected substitution into a milder policy refusal.
func TestHandleDEKRewrapForMember_ChangedIsRefusedUnderBothPolicies(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "strict off"
		if strict {
			name = "strict on"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWrapFixture(t)
			original, swapped := newTrustKey(t), newTrustKey(t)

			if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
				WrappedForMeB64: fixture.wrapped,
				OtherPublicKey:  original.pair.PublicKey,
				OwnerAccountID:  pinOwnerA,
				OtherAccountID:  pinPeer,
			}); !resp.Success {
				t.Fatalf("seed wrap failed: %s", resp.Error)
			}
			setStrictMode(t, fixture.deps, strict)

			resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
				WrappedForMeB64: fixture.wrapped,
				OtherPublicKey:  swapped.pair.PublicKey,
				OwnerAccountID:  pinOwnerA,
				OtherAccountID:  pinPeer,
			})
			if resp.Success {
				t.Fatal("an unexplained key change was wrapped")
			}
			if resp.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
				t.Fatalf("error_code = %q, want peer_key_changed", resp.ErrorCode)
			}
			detail, ok := resp.Data.(proto.PeerKeyChangedResponseData)
			if !ok {
				t.Fatalf("refusal data = %+v, want PeerKeyChangedResponseData", resp.Data)
			}
			if detail.ObservedFingerprint != swapped.fingerprint ||
				detail.PinnedFingerprint != original.fingerprint {
				t.Fatalf("refusal fingerprints = %+v, want observed=%q pinned=%q",
					detail, swapped.fingerprint, original.fingerprint)
			}
		})
	}
}

// Strict mode is a rule about pins, and a call that names no account has no
// pin to judge. The pre-0.0.31 shape keeps working exactly as it did.
func TestHandleDEKRewrapForMember_StrictLeavesLegacyCallsAlone(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("strict mode refused a legacy call: %s (%s)", resp.Error, resp.ErrorCode)
	}
	data := resp.Data.(proto.DEKRewrapForMemberResponseData)
	if data.PinEnforced || data.PinState != "" {
		t.Fatalf("legacy call reported enforcement: %+v", data)
	}
	if data.EncryptedForOtherB64 == "" {
		t.Fatal("no wrap produced")
	}
}

// The batch action refuses whole, the same way it does for `changed`: one
// unverified member stops the rotation before any member is wrapped.
func TestHandleDEKUnwrapAndRewrapForMany_StrictRefusesWholeBatch(t *testing.T) {
	fixture := newWrapFixture(t)
	verified, unchecked := newTrustKey(t), newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		Fingerprint:    verified.fingerprint,
		PublicKey:      verified.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}

	setStrictMode(t, fixture.deps, true)

	resp := HandleDEKUnwrapAndRewrapForMany(fixture.deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: fixture.wrapped,
		OwnerAccountID:  pinOwnerA,
		Recipients: []proto.DEKRewrapRecipient{
			{AccountID: pinPeer, PublicKey: verified.pair.PublicKey},
			{AccountID: pinPeer2, PublicKey: unchecked.pair.PublicKey},
		},
	})
	if resp.Success {
		t.Fatal("batch succeeded with one unverified recipient")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
		t.Fatalf("error_code = %q, want peer_key_unverified", resp.ErrorCode)
	}
	assertNoWrapOutput(t, resp, "encrypted_for_recipients_b64")
	if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerA, pinPeer2); err == nil {
		t.Fatal("a refused batch left a pin behind")
	}
}

// assertNoWrapOutput serializes the whole envelope, because a refusal that
// carried ciphertext in some nested field would still be a refusal that
// handed the key over.
func assertNoWrapOutput(t *testing.T, resp proto.BaseResponse, field string) {
	t.Helper()
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(encoded), field) {
		t.Fatalf("refusal envelope carries %s: %s", field, encoded)
	}
}
