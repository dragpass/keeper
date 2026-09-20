// peer_key_pin_test.go — the four pin actions and pin enforcement inside the
// two wrap actions.
//
// These run against MemorySecretStore through the real keychain helpers, so a
// pin written by a wrap is the same record peer_key_pin_get reads back.

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	pinOwnerA = "11111111-1111-4111-8111-111111111111"
	pinOwnerB = "22222222-2222-4222-8222-222222222222"
	pinPeer   = "33333333-3333-4333-8333-333333333333"
	pinPeer2  = "55555555-5555-4555-8555-555555555555"
)

// wrapFixture is a DEK already wrapped to the Keeper's own active key, which
// is what both wrap actions take as input.
type wrapFixture struct {
	deps    Deps
	wrapped string
}

func newWrapFixture(t *testing.T) wrapFixture {
	t.Helper()
	deps, _, store := newTestDeps(t)
	myPubPEM, _ := setupHandlerKeyPair(t, store)
	myPub, err := crypto.ParsePublicKey(myPubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}
	sealed, err := crypto.EncryptData(myPub, dek)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	return wrapFixture{deps: deps, wrapped: base64.StdEncoding.EncodeToString(sealed)}
}

func mustGetPin(t *testing.T, deps Deps, owner, peer string) keychain.PeerKeyPin {
	t.Helper()
	pin, err := keychain.GetPeerKeyPin(deps.Store, owner, peer)
	if err != nil {
		t.Fatalf("GetPeerKeyPin(%s,%s): %v", owner, peer, err)
	}
	return pin
}

// ─── the wrap path ──────────────────────────────────────────────────────

// The first wrap to a peer records the key it used.
func TestHandleDEKRewrapForMember_FirstWrapPinsTOFU(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !resp.Success {
		t.Fatalf("first wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKRewrapForMemberResponseData)
	if !data.PinEnforced {
		t.Fatal("pin_enforced=false on a request that named an account")
	}
	if data.PinState != string(keychain.PeerKeyPinStateTOFU) {
		t.Fatalf("pin_state = %q, want tofu", data.PinState)
	}
	if data.EncryptedForOtherB64 == "" {
		t.Fatal("no wrap produced")
	}

	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if pin.Fingerprint != peer.fingerprint {
		t.Fatalf("pinned %q, want the key that was wrapped to", pin.Fingerprint)
	}
	if pin.State != keychain.PeerKeyPinStateTOFU || pin.FirstSeenAt != pin.LastSeenAt {
		t.Fatalf("pin = %+v, want a fresh tofu pin", pin)
	}
}

// A key swapped without a chain refuses the wrap, produces no ciphertext, and
// leaves the record alone.
func TestHandleDEKRewrapForMember_UnexplainedKeyChangeRefused(t *testing.T) {
	fixture := newWrapFixture(t)
	original, swapped := newTrustKey(t), newTrustKey(t)

	first := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  original.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if !first.Success {
		t.Fatalf("first wrap failed: %s", first.Error)
	}

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  swapped.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	})
	if resp.Success {
		t.Fatal("wrap succeeded against a key that changed with no rotation chain")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
		t.Fatalf("error_code = %q, want peer_key_changed", resp.ErrorCode)
	}
	if resp.Data != nil {
		t.Fatalf("refusal carried data: %+v", resp.Data)
	}
	// Serialization check: no wrap output anywhere in the envelope.
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(encoded), "encrypted_for_other_b64") {
		t.Fatalf("refusal envelope carries a wrap: %s", encoded)
	}

	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if pin.Fingerprint != original.fingerprint {
		t.Fatalf("pin moved to %q on a refusal", pin.Fingerprint)
	}
}

// A valid voluntary chain lets the wrap through and advances the pin.
func TestHandleDEKRewrapForMember_ValidChainRotatesPin(t *testing.T) {
	fixture := newWrapFixture(t)
	original, next := newTrustKey(t), newTrustKey(t)

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  original.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("first wrap failed: %s", resp.Error)
	}

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  next.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
		RotationStatements: []proto.KeyRotationStatement{
			statementFor(t, original, next, pinPeer, proto.KeyRotationReasonVoluntary),
		},
	})
	if !resp.Success {
		t.Fatalf("valid chain refused: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKRewrapForMemberResponseData)
	if data.PinState != string(keychain.PeerKeyPinStateRotated) {
		t.Fatalf("pin_state = %q, want rotated", data.PinState)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.Fingerprint != next.fingerprint {
		t.Fatalf("pin = %q, want the new key", pin.Fingerprint)
	}
}

// Calling without account ids behaves exactly as it did before 0.0.31.
func TestHandleDEKRewrapForMember_LegacyCallStaysOpen(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("legacy call failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKRewrapForMemberResponseData)
	if data.PinEnforced || data.PinState != "" {
		t.Fatalf("legacy call reported enforcement: %+v", data)
	}
	if _, err := keychain.GetPeerKeyPin(fixture.deps.Store, pinOwnerA, pinPeer); err == nil {
		t.Fatal("legacy call wrote a pin")
	}
}

// The two ids travel together. One without the other is a caller bug.
func TestDEKRewrapForMember_Validate_RequiresBothAccountIDs(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte("x"))
	pem := "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
	cases := []struct {
		name string
		req  proto.DEKRewrapForMemberRequest
	}{
		{"peer without owner", proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: wrapped, OtherPublicKey: pem, OtherAccountID: pinPeer,
		}},
		{"owner without peer", proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: wrapped, OtherPublicKey: pem, OwnerAccountID: pinOwnerA,
		}},
		{"uppercase uuid", proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: wrapped, OtherPublicKey: pem,
			OwnerAccountID: pinOwnerA, OtherAccountID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
		}},
		{"nil uuid", proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: wrapped, OtherPublicKey: pem,
			OwnerAccountID: pinOwnerA, OtherAccountID: "00000000-0000-0000-0000-000000000000",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.req.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// Rotation is the dangerous call: every recipient is judged before the first
// wrap, so one bad key refuses the whole batch with no partial output.
func TestHandleDEKUnwrapAndRewrapForMany_RefusesWholeBatch(t *testing.T) {
	fixture := newWrapFixture(t)
	good, original, swapped := newTrustKey(t), newTrustKey(t), newTrustKey(t)

	seed := HandleDEKUnwrapAndRewrapForMany(fixture.deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: fixture.wrapped,
		OwnerAccountID:  pinOwnerA,
		Recipients: []proto.DEKRewrapRecipient{
			{AccountID: pinPeer, PublicKey: good.pair.PublicKey},
			{AccountID: pinPeer2, PublicKey: original.pair.PublicKey},
		},
	})
	if !seed.Success {
		t.Fatalf("seed wrap failed: %s", seed.Error)
	}
	seedData := seed.Data.(proto.DEKUnwrapAndRewrapForManyResponseData)
	if !seedData.PinEnforced || len(seedData.PinStates) != 2 {
		t.Fatalf("seed response = %+v, want two enforced states", seedData)
	}

	// The second member's key is now a different one, with nothing to explain it.
	resp := HandleDEKUnwrapAndRewrapForMany(fixture.deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: fixture.wrapped,
		OwnerAccountID:  pinOwnerA,
		Recipients: []proto.DEKRewrapRecipient{
			{AccountID: pinPeer, PublicKey: good.pair.PublicKey},
			{AccountID: pinPeer2, PublicKey: swapped.pair.PublicKey},
		},
	})
	if resp.Success {
		t.Fatal("batch succeeded with one unexplained key change")
	}
	if resp.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
		t.Fatalf("error_code = %q, want peer_key_changed", resp.ErrorCode)
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if strings.Contains(string(encoded), "encrypted_for_recipients_b64") {
		t.Fatalf("refusal envelope carries wraps: %s", encoded)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer2); pin.Fingerprint != original.fingerprint {
		t.Fatalf("pin moved to %q on a refused batch", pin.Fingerprint)
	}
}

// A recipient with no account id is the org archive key: wrapped, not pinned.
func TestHandleDEKUnwrapAndRewrapForMany_ExemptRecipient(t *testing.T) {
	fixture := newWrapFixture(t)
	member, archive := newTrustKey(t), newTrustKey(t)

	resp := HandleDEKUnwrapAndRewrapForMany(fixture.deps, proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: fixture.wrapped,
		OwnerAccountID:  pinOwnerA,
		Recipients: []proto.DEKRewrapRecipient{
			{AccountID: pinPeer, PublicKey: member.pair.PublicKey},
			{PublicKey: archive.pair.PublicKey},
		},
	})
	if !resp.Success {
		t.Fatalf("wrap failed: %s", resp.Error)
	}
	data := resp.Data.(proto.DEKUnwrapAndRewrapForManyResponseData)
	if len(data.EncryptedForRecipientsB64) != 2 {
		t.Fatalf("got %d wraps, want 2", len(data.EncryptedForRecipientsB64))
	}
	want := []string{string(keychain.PeerKeyPinStateTOFU), peerKeyPinStateExempt}
	if len(data.PinStates) != 2 || data.PinStates[0] != want[0] || data.PinStates[1] != want[1] {
		t.Fatalf("pin_states = %v, want %v", data.PinStates, want)
	}
}

func TestDEKUnwrapAndRewrapForMany_Validate_RecipientShapes(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte("x"))
	pem := "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"

	tooMany := make([]proto.DEKRewrapRecipient, proto.DEKRewrapMaxRecipients+1)
	for i := range tooMany {
		tooMany[i] = proto.DEKRewrapRecipient{PublicKey: pem}
	}
	tooManyStatements := make([]proto.KeyRotationStatement, proto.KeyRotationMaxStatements+1)

	cases := []struct {
		name string
		req  proto.DEKUnwrapAndRewrapForManyRequest
	}{
		{"both shapes at once", proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64:     wrapped,
			Recipients:          []proto.DEKRewrapRecipient{{PublicKey: pem}},
			RecipientPublicKeys: []string{pem},
		}},
		{"neither shape", proto.DEKUnwrapAndRewrapForManyRequest{WrappedForMeB64: wrapped}},
		{"account without owner", proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64: wrapped,
			Recipients:      []proto.DEKRewrapRecipient{{AccountID: pinPeer, PublicKey: pem}},
		}},
		{"over the recipient cap", proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64: wrapped, Recipients: tooMany,
		}},
		{"over the statement cap", proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64: wrapped,
			OwnerAccountID:  pinOwnerA,
			Recipients: []proto.DEKRewrapRecipient{
				{AccountID: pinPeer, PublicKey: pem, RotationStatements: tooManyStatements},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.req.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}

	// The legacy flat list still validates on its own.
	legacy := proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: wrapped, RecipientPublicKeys: []string{pem},
	}
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy shape rejected: %v", err)
	}
	if list := legacy.RecipientList(); len(list) != 1 || list[0].AccountID != "" {
		t.Fatalf("RecipientList() = %+v, want one account-less recipient", list)
	}
}

// ─── the four pin actions ───────────────────────────────────────────────

func TestHandlePeerKeyPinGetAndList(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	missing := HandlePeerKeyPinGet(fixture.deps, proto.PeerKeyPinGetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	})
	if !missing.Success {
		t.Fatalf("get on an unknown peer failed: %s", missing.Error)
	}
	if got := missing.Data.(proto.PeerKeyPinGetResponseData); got.Found || got.Pin != nil {
		t.Fatalf("unknown peer reported %+v, want found=false", got)
	}

	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  peer.pair.PublicKey,
		OwnerAccountID:  pinOwnerA,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("wrap failed: %s", resp.Error)
	}

	found := HandlePeerKeyPinGet(fixture.deps, proto.PeerKeyPinGetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	})
	got := found.Data.(proto.PeerKeyPinGetResponseData)
	if !got.Found || got.Pin == nil {
		t.Fatalf("get after a wrap reported %+v", got)
	}
	if got.Pin.Fingerprint != peer.fingerprint || got.Pin.State != string(keychain.PeerKeyPinStateTOFU) {
		t.Fatalf("pin = %+v, want the wrapped key at tofu", got.Pin)
	}
	if got.Pin.FirstSeenAt != got.Pin.LastSeenAt {
		t.Fatalf("first_seen_at %d != last_seen_at %d after one wrap", got.Pin.FirstSeenAt, got.Pin.LastSeenAt)
	}

	listed := HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{OwnerAccountID: pinOwnerA})
	pins := listed.Data.(proto.PeerKeyPinListResponseData).Pins
	if len(pins) != 1 || pins[0].AccountID != pinPeer {
		t.Fatalf("list = %+v, want the one pin", pins)
	}

	// No key material in any of it.
	encoded, err := json.Marshal(listed)
	if err != nil {
		t.Fatalf("marshal list response: %v", err)
	}
	if strings.Contains(string(encoded), "BEGIN") || strings.Contains(string(encoded), "public_key") {
		t.Fatalf("pin list response carries key material: %s", encoded)
	}
}

func TestHandlePeerKeyPinVerify(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	// Verification works before anything has been observed.
	resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		Fingerprint:    peer.fingerprint,
		PublicKey:      peer.pair.PublicKey,
	})
	if !resp.Success {
		t.Fatalf("verify failed: %s", resp.Error)
	}
	data := resp.Data.(proto.PeerKeyPinVerifyResponseData)
	if data.State != string(keychain.PeerKeyPinStateVerified) || data.Fingerprint != peer.fingerprint {
		t.Fatalf("verify response = %+v", data)
	}
	pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer)
	if pin.State != keychain.PeerKeyPinStateVerified || pin.VerifiedAt == 0 {
		t.Fatalf("pin = %+v, want verified with a timestamp", pin)
	}
}

// The check that makes the action worth having: a fingerprint the user read
// out must match the key the server is serving, or nothing is promoted.
func TestHandlePeerKeyPinVerify_MismatchLeavesPinAlone(t *testing.T) {
	fixture := newWrapFixture(t)
	confirmed, served := newTrustKey(t), newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		Fingerprint:    confirmed.fingerprint,
		PublicKey:      confirmed.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("seed verify failed: %s", resp.Error)
	}

	resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA,
		AccountID:      pinPeer,
		Fingerprint:    confirmed.fingerprint, // what the human checked
		PublicKey:      served.pair.PublicKey, // what the server is handing out
	})
	if resp.Success {
		t.Fatal("verify accepted a fingerprint that does not match the key")
	}
	if resp.ErrorCode != string(errs.ErrCodeCryptoFailure) {
		t.Fatalf("error_code = %q, want crypto_failure", resp.ErrorCode)
	}
	if pin := mustGetPin(t, fixture.deps, pinOwnerA, pinPeer); pin.Fingerprint != confirmed.fingerprint {
		t.Fatalf("pin moved to %q on a mismatch", pin.Fingerprint)
	}
}

func TestHandlePeerKeyPinForget_Idempotent(t *testing.T) {
	fixture := newWrapFixture(t)
	peer := newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: peer.fingerprint, PublicKey: peer.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("seed verify failed: %s", resp.Error)
	}

	first := HandlePeerKeyPinForget(fixture.deps, proto.PeerKeyPinForgetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	})
	if !first.Success || !first.Data.(proto.PeerKeyPinForgetResponseData).Forgotten {
		t.Fatalf("first forget = %+v, want forgotten=true", first)
	}

	second := HandlePeerKeyPinForget(fixture.deps, proto.PeerKeyPinForgetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	})
	if !second.Success {
		t.Fatalf("second forget failed: %s", second.Error)
	}
	if second.Data.(proto.PeerKeyPinForgetResponseData).Forgotten {
		t.Fatal("second forget reported something forgotten")
	}

	listed := HandlePeerKeyPinList(fixture.deps, proto.PeerKeyPinListRequest{OwnerAccountID: pinOwnerA})
	if pins := listed.Data.(proto.PeerKeyPinListResponseData).Pins; len(pins) != 0 {
		t.Fatalf("list after forget = %+v, want empty", pins)
	}
}

// Two accounts on one device keep separate trust. A's verification is not
// visible to B, and B's forget does not reach A.
func TestPeerKeyPin_OwnerScopeDoesNotLeak(t *testing.T) {
	fixture := newWrapFixture(t)
	keyA, keyB := newTrustKey(t), newTrustKey(t)

	if resp := HandlePeerKeyPinVerify(fixture.deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: keyA.fingerprint, PublicKey: keyA.pair.PublicKey,
	}); !resp.Success {
		t.Fatalf("owner A verify failed: %s", resp.Error)
	}
	if resp := HandleDEKRewrapForMember(fixture.deps, proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: fixture.wrapped,
		OtherPublicKey:  keyB.pair.PublicKey,
		OwnerAccountID:  pinOwnerB,
		OtherAccountID:  pinPeer,
	}); !resp.Success {
		t.Fatalf("owner B wrap failed: %s", resp.Error)
	}

	gotB := HandlePeerKeyPinGet(fixture.deps, proto.PeerKeyPinGetRequest{
		OwnerAccountID: pinOwnerB, AccountID: pinPeer,
	}).Data.(proto.PeerKeyPinGetResponseData)
	if gotB.Pin.State != string(keychain.PeerKeyPinStateTOFU) || gotB.Pin.Fingerprint != keyB.fingerprint {
		t.Fatalf("owner B sees %+v, want its own tofu pin", gotB.Pin)
	}

	if resp := HandlePeerKeyPinForget(fixture.deps, proto.PeerKeyPinForgetRequest{
		OwnerAccountID: pinOwnerB, AccountID: pinPeer,
	}); !resp.Success {
		t.Fatalf("owner B forget failed: %s", resp.Error)
	}

	gotA := HandlePeerKeyPinGet(fixture.deps, proto.PeerKeyPinGetRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
	}).Data.(proto.PeerKeyPinGetResponseData)
	if !gotA.Found || gotA.Pin.State != string(keychain.PeerKeyPinStateVerified) {
		t.Fatalf("owner A pin after B's forget = %+v, want its verified pin intact", gotA)
	}
}

func TestPeerKeyPinActions_Validation(t *testing.T) {
	deps, _, _ := newTestDeps(t)
	peer := newTrustKey(t)

	if resp := HandlePeerKeyPinList(deps, proto.PeerKeyPinListRequest{OwnerAccountID: "nope"}); resp.Success {
		t.Fatal("list accepted a non-UUID owner")
	}
	if resp := HandlePeerKeyPinGet(deps, proto.PeerKeyPinGetRequest{OwnerAccountID: pinOwnerA}); resp.Success {
		t.Fatal("get accepted a missing account_id")
	}
	if resp := HandlePeerKeyPinForget(deps, proto.PeerKeyPinForgetRequest{AccountID: pinPeer}); resp.Success {
		t.Fatal("forget accepted a missing owner_account_id")
	}
	if resp := HandlePeerKeyPinVerify(deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: strings.Repeat("A", 64), PublicKey: peer.pair.PublicKey,
	}); resp.Success {
		t.Fatal("verify accepted an uppercase fingerprint")
	}
	if resp := HandlePeerKeyPinVerify(deps, proto.PeerKeyPinVerifyRequest{
		OwnerAccountID: pinOwnerA, AccountID: pinPeer,
		Fingerprint: peer.fingerprint, PublicKey: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----",
	}); resp.Success {
		t.Fatal("verify accepted a PEM header wrapped around nothing")
	}
}
