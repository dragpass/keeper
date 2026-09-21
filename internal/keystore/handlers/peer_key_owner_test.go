// peer_key_owner_test.go — owner trust-on-first-use across every action that
// takes an owner_account_id, and the reset that unbinds a device.
//
// The case that drives the file is the audit's: a server that swaps a member's
// public key *and* reports a different account id used to get a `tofu` wrap
// out of an empty namespace, while the fingerprint a human had verified sat
// untouched in the old one. TestPeerKeyOwner_EmptyNamespaceAttackIsRefused
// replays exactly that and expects a refusal.

package handlers

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// switchPeerKeyOwner clears the recorded owner so the next request binds a
// different one. This is the options-page escape hatch; tests that legitimately
// use two owners on one device go through it the way a real device would.
func switchPeerKeyOwner(t *testing.T, deps Deps) {
	t.Helper()
	if resp := HandlePeerKeyOwnerReset(deps, proto.PeerKeyOwnerResetRequest{}); !resp.Success {
		t.Fatalf("peer key owner reset failed: %s", resp.Error)
	}
}

func recordedOwner(t *testing.T, deps Deps) (string, bool) {
	t.Helper()
	owner, found, err := keychain.GetPeerKeyOwner(deps.Store)
	if err != nil {
		t.Fatalf("GetPeerKeyOwner: %v", err)
	}
	return owner.AccountID, found
}

// ─── recording ──────────────────────────────────────────────────────────

// The first request that names an owner binds the device to it.
func TestPeerKeyOwner_RecordedOnFirstUse(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if _, found := recordedOwner(t, fixture.deps); found {
		t.Fatal("a fresh device already has an owner recorded")
	}

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !resp.Success {
		t.Fatalf("first wrap failed: %s", resp.Error)
	}

	got, found := recordedOwner(t, fixture.deps)
	if !found || got != pinOwnerA {
		t.Fatalf("recorded owner = %q found=%t, want %q", got, found, pinOwnerA)
	}
}

// A pin action binds the device just as a wrap does — the owner half of the
// keyring name is the same field whichever action carries it.
func TestPeerKeyOwner_RecordedByPinActionsToo(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	resp := HandlePeerKeyPinList(deps, proto.PeerKeyPinListRequest{OwnerAccountID: pinOwnerA})
	if !resp.Success {
		t.Fatalf("pin list failed: %s", resp.Error)
	}

	got, found := recordedOwner(t, deps)
	if !found || got != pinOwnerA {
		t.Fatalf("recorded owner = %q found=%t, want %q", got, found, pinOwnerA)
	}
}

// A legacy wrap carries no owner id, so there is no namespace to bind and
// nothing is recorded.
func TestPeerKeyOwner_LegacyWrapRecordsNothing(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("legacy wrap failed: %s", resp.Error)
	}
	if _, found := recordedOwner(t, fixture.deps); found {
		t.Fatal("a wrap with no owner id bound the device")
	}
}

// ─── refusing a different owner ─────────────────────────────────────────

// Every action that takes an owner id refuses one that disagrees, and none of
// them touches a pin on the way out.
func TestPeerKeyOwner_MismatchRefusesEveryAction(t *testing.T) {
	fixture := newWrapFixture(t)
	peer, intruderKey := newTrustKey(t), newTrustKey(t)

	// Owner A binds the device and pins its peer.
	first := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !first.Success {
		t.Fatalf("owner A wrap failed: %s", first.Error)
	}
	before := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)

	cases := []struct {
		name string
		call func() proto.BaseResponse
	}{
		{"dek_rewrap_for_member", func() proto.BaseResponse {
			return HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
				WrappedForMeB64: fixture.wrapped,
				OtherPublicKey:  intruderKey.pair.PublicKey,
				OwnerAccountID:  pinOwnerB,
				OtherAccountID:  pinPeer,
			})
		}},
		{"dek_unwrap_and_rewrap_for_many", func() proto.BaseResponse {
			return HandleDEKUnwrapAndRewrapForMany(fixture.deps, proto.DEKUnwrapAndRewrapForManyRequest{
				WrappedForMeB64: fixture.wrapped,
				OwnerAccountID:  pinOwnerB,
				Recipients: []proto.DEKRewrapRecipient{
					{AccountID: pinPeer, PublicKey: intruderKey.pair.PublicKey},
				},
			})
		}},
		{"peer_key_pin_list", func() proto.BaseResponse {
			return HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{
				OwnerAccountID: pinOwnerB,
			})
		}},
		{"peer_key_pin_get", func() proto.BaseResponse {
			return HandlePeerKeyPinGet(fixture.deps, proto.PeerKeyPinGetRequest{
				OwnerAccountID: pinOwnerB, AccountID: pinPeer,
			})
		}},
		{"peer_key_pin_verify", func() proto.BaseResponse {
			return HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
				OwnerAccountID: pinOwnerB, AccountID: pinPeer,
				Fingerprint: intruderKey.fingerprint, PublicKey: intruderKey.pair.PublicKey,
			})
		}},
		{"peer_key_pin_forget", func() proto.BaseResponse {
			return HandlePeerKeyPinForget(fixture.deps, proto.PeerKeyPinForgetRequest{
				OwnerAccountID: pinOwnerB, AccountID: pinPeer,
			})
		}},
		{"peer_key_chain_evaluate", func() proto.BaseResponse {
			return HandlePeerKeyChainEvaluate(fixture.deps, proto.PeerKeyChainEvaluateRequest{
				OwnerAccountID: pinOwnerB, AccountID: pinPeer,
				PublicKey: intruderKey.pair.PublicKey,
			})
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := c.call()
			if resp.Success {
				t.Fatalf("%s accepted an owner the device never recorded", c.name)
			}
			if resp.ErrorCode != string(errs.ErrCodePeerKeyOwnerMismatch) {
				t.Fatalf("error_code = %q, want peer_key_owner_mismatch", resp.ErrorCode)
			}
			if resp.Data != nil {
				t.Fatalf("refusal carried data: %+v", resp.Data)
			}
			// No pin moved, in either namespace.
			if after := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); after != before {
				t.Fatalf("owner A's pin changed: %+v, want %+v", after, before)
			}
			if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerB, pinPeer); err == nil {
				t.Fatal("a pin was written into the refused owner's namespace")
			}
		})
	}
}

// The audit's attack, end to end. The server swaps the peer's key and reports
// a different account id at the same time. Before owner TOFU this read an
// empty namespace, called the peer a first observation, and wrapped. Now it is
// refused and the verified pin stays the one being consulted.
func TestPeerKeyOwner_EmptyNamespaceAttackIsRefused(t *testing.T) {
	fixture := newWrapFixture(t)
	real, attacker := newTrustKey(t), newTrustKey(t)

	// A human compared the peer's real key out of band.
	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: real.fingerprint, PublicKey: real.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}

	// Lie one on its own is already refused: same owner, swapped key.
	sameOwner := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  attacker.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if sameOwner.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
		t.Fatalf("swapped key under the right owner gave %q, want peer_key_changed", sameOwner.ErrorCode)
	}

	// Lie two added: a different account id moves the lookup into a namespace
	// nothing was ever written to.
	bothLies := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  attacker.pair.PublicKey,
		OwnerAccountID:  pinOwnerB,
		OtherAccountID:  pinPeer,
	})
	if bothLies.Success {
		t.Fatal("the empty-namespace attack produced a wrap")
	}
	if bothLies.ErrorCode != string(errs.ErrCodePeerKeyOwnerMismatch) {
		t.Fatalf("error_code = %q, want peer_key_owner_mismatch", bothLies.ErrorCode)
	}

	// And the pin list the SPA draws its blocked banner from is refused
	// rather than answered empty.
	list := HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{OwnerAccountID: pinOwnerB})
	if list.Success {
		t.Fatalf("pin list answered for an owner the device never recorded: %+v", list.Data)
	}

	// The verified pin is untouched and still the one that answers.
	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if pin.State != keychain.PeerKeyPinStateVerified || pin.Fingerprint != real.fingerprint {
		t.Fatalf("pin = %+v, want the verified real key", pin)
	}
}

// ─── reset ──────────────────────────────────────────────────────────────

// Reset clears the record, is idempotent, and leaves pins where they are.
func TestHandlePeerKeyOwnerReset(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("owner A wrap failed: %s", resp.Error)
	}

	first := HandlePeerKeyOwnerReset(fixture.deps, proto.PeerKeyOwnerResetRequest{})
	if !first.Success {
		t.Fatalf("reset failed: %s", first.Error)
	}
	if data := first.Data.(proto.PeerKeyOwnerResetResponseData); !data.Reset {
		t.Fatal("reset reported nothing to clear")
	}
	if _, found := recordedOwner(t, fixture.deps); found {
		t.Fatal("the owner survived the reset")
	}

	second := HandlePeerKeyOwnerReset(fixture.deps, proto.PeerKeyOwnerResetRequest{})
	if !second.Success {
		t.Fatalf("second reset failed: %s", second.Error)
	}
	if data := second.Data.(proto.PeerKeyOwnerResetResponseData); data.Reset {
		t.Fatal("a second reset claimed to clear something")
	}

	// Owner A's pin is still there, so signing back in finds it.
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.Fingerprint != peer.fingerprint {
		t.Fatalf("pin = %+v, want owner A's record intact", pin)
	}

	// And the device is free to bind a different owner now.
	if resp := HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{
		OwnerAccountID: pinOwnerB,
	}); !resp.Success {
		t.Fatalf("owner B refused after a reset: %s", resp.Error)
	}
	if got, _ := recordedOwner(t, fixture.deps); got != pinOwnerB {
		t.Fatalf("recorded owner = %q, want %q", got, pinOwnerB)
	}
}

// Reset is the only way the record changes. Nothing else clears or replaces
// it, including a forget of every pin the owner holds.
func TestPeerKeyOwner_ForgetDoesNotUnbindTheDevice(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("owner A wrap failed: %s", resp.Error)
	}
	if resp := HandlePeerKeyPinForget(fixture.deps, proto.PeerKeyPinForgetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	}); !resp.Success {
		t.Fatalf("forget failed: %s", resp.Error)
	}

	if got, found := recordedOwner(t, fixture.deps); !found || got != pinOwnerA {
		t.Fatalf("recorded owner = %q found=%t, want %q to survive a forget", got, found, pinOwnerA)
	}
	if resp := HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{
		OwnerAccountID: pinOwnerB,
	}); resp.Success {
		t.Fatal("forgetting every pin unbound the device")
	}
}

// The policy actions take no owner id, so they are outside this check and
// stay reachable whatever the device is bound to.
func TestPeerKeyOwner_PolicyActionsAreUnaffected(t *testing.T) {
	deps, _, _ := newTestDeps(t)

	if resp := HandlePeerKeyPinList(deps, proto.PeerKeyPinListRequest{
		OwnerAccountID: pinOwnerA,
	}); !resp.Success {
		t.Fatalf("binding call failed: %s", resp.Error)
	}

	if resp := HandlePeerKeyPolicyGet(deps, proto.PeerKeyPolicyGetRequest{}); !resp.Success {
		t.Fatalf("policy get refused on a bound device: %s", resp.Error)
	}
	on := true
	if resp := HandlePeerKeyPolicySet(deps, proto.PeerKeyPolicySetRequest{
		RequireVerifiedPeers: &on,
	}); !resp.Success {
		t.Fatalf("policy set refused on a bound device: %s", resp.Error)
	}
}
