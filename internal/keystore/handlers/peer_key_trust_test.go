// peer_key_trust_test.go — every branch of the D3 state machine.
//
// evaluatePeerKeyTrust is pure, so these run without a store, a clock, or a
// keypair in the Keychain. The cases are the verification list from the
// contract §9 turned into a table: the ones that must allow, and the eight
// distinct ways a chain can fail to explain a key change.

package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	trustPeerAccount  = "33333333-3333-4333-8333-333333333333"
	trustOtherAccount = "44444444-4444-4444-8444-444444444444"
	trustRotatedAt    = 1758240000
	trustNow          = 1758246000
)

// trustKey is a test keypair plus the two forms the trust model needs.
type trustKey struct {
	pair        *crypto.KeyPair
	priv        *rsa.PrivateKey
	fingerprint string
	publicB64   string
}

func newTrustKey(t *testing.T) trustKey {
	t.Helper()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	priv, err := crypto.ParsePrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return trustKey{
		pair:        pair,
		priv:        priv,
		fingerprint: crypto.AccountKeyFingerprint([]byte(pair.PublicKey)),
		publicB64:   base64.StdEncoding.EncodeToString([]byte(pair.PublicKey)),
	}
}

func signTrust(t *testing.T, priv *rsa.PrivateKey, data string) string {
	t.Helper()
	signature, err := crypto.SignData(priv, data)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

// statementFor builds a well-formed, correctly signed statement carrying old
// to new. Tests that need a broken one start here and damage one field, so
// what each case is actually testing stays visible.
func statementFor(t *testing.T, old, next trustKey, accountID, reason string) proto.KeyRotationStatement {
	t.Helper()
	canonical := proto.KeyRotationCanonical(
		accountID, old.fingerprint, next.fingerprint, trustRotatedAt, reason,
	)
	return proto.KeyRotationStatement{
		AccountID:      accountID,
		OldFingerprint: old.fingerprint,
		NewFingerprint: next.fingerprint,
		RotatedAt:      trustRotatedAt,
		Reason:         reason,
		OldPublicKey:   old.publicB64,
		NewPublicKey:   next.publicB64,
		OldSignature:   signTrust(t, old.priv, canonical),
		NewSignature:   signTrust(t, next.priv, canonical),
	}
}

func verifiedPin(fingerprint string) *keychain.PeerKeyPin {
	return &keychain.PeerKeyPin{
		V:           keychain.PeerKeyPinVersion,
		Fingerprint: fingerprint,
		State:       keychain.PeerKeyPinStateVerified,
		FirstSeenAt: 1758000000,
		LastSeenAt:  1758100000,
		VerifiedAt:  1758100000,
	}
}

func TestEvaluatePeerKeyTrust_FirstObservationPins(t *testing.T) {
	key := newTrustKey(t)

	outcome := evaluatePeerKeyTrust(nil, trustPeerAccount, key.fingerprint, nil, trustNow)

	if !outcome.Allowed {
		t.Fatalf("first observation refused: %s", outcome.Reason)
	}
	if outcome.State != keychain.PeerKeyPinStateTOFU {
		t.Fatalf("state = %q, want tofu", outcome.State)
	}
	if outcome.Pin.Fingerprint != key.fingerprint {
		t.Fatalf("pinned %q, want the observed fingerprint", outcome.Pin.Fingerprint)
	}
	if outcome.Pin.FirstSeenAt != trustNow || outcome.Pin.LastSeenAt != trustNow {
		t.Fatalf("times = %d/%d, want both %d", outcome.Pin.FirstSeenAt, outcome.Pin.LastSeenAt, trustNow)
	}
	if outcome.Pin.VerifiedAt != 0 {
		t.Fatal("first observation must not be marked verified")
	}
}

// The same key again keeps whatever trust it had and only moves last_seen_at.
func TestEvaluatePeerKeyTrust_UnchangedKeyKeepsState(t *testing.T) {
	key := newTrustKey(t)
	existing := verifiedPin(key.fingerprint)

	outcome := evaluatePeerKeyTrust(existing, trustPeerAccount, key.fingerprint, nil, trustNow)

	if !outcome.Allowed {
		t.Fatalf("unchanged key refused: %s", outcome.Reason)
	}
	if outcome.State != keychain.PeerKeyPinStateVerified {
		t.Fatalf("state = %q, want verified to survive", outcome.State)
	}
	if outcome.Pin.VerifiedAt != existing.VerifiedAt {
		t.Fatalf("verified_at = %d, want %d", outcome.Pin.VerifiedAt, existing.VerifiedAt)
	}
	if outcome.Pin.LastSeenAt != trustNow {
		t.Fatalf("last_seen_at = %d, want %d", outcome.Pin.LastSeenAt, trustNow)
	}
	if outcome.Pin.FirstSeenAt != existing.FirstSeenAt {
		t.Fatal("first_seen_at moved on an unchanged key")
	}
}

// A valid voluntary chain advances the pin and takes `verified` away with it.
func TestEvaluatePeerKeyTrust_ValidChainRotates(t *testing.T) {
	old, next := newTrustKey(t), newTrustKey(t)
	existing := verifiedPin(old.fingerprint)
	chain := []proto.KeyRotationStatement{
		statementFor(t, old, next, trustPeerAccount, proto.KeyRotationReasonVoluntary),
	}

	outcome := evaluatePeerKeyTrust(existing, trustPeerAccount, next.fingerprint, chain, trustNow)

	if !outcome.Allowed {
		t.Fatalf("valid chain refused: %s", outcome.Reason)
	}
	if outcome.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("state = %q, want rotated", outcome.State)
	}
	if outcome.Pin.Fingerprint != next.fingerprint {
		t.Fatal("pin did not advance to the observed key")
	}
	if outcome.Pin.VerifiedAt != 0 {
		t.Fatal("verified_at survived a rotation; a human checked the previous key, not this one")
	}
	if outcome.Pin.LastRotationFingerprint != old.fingerprint {
		t.Fatalf("last_rotation_fingerprint = %q, want the previous fingerprint", outcome.Pin.LastRotationFingerprint)
	}
}

// A recovery is an ordinary operational event, so it succeeds the same way.
func TestEvaluatePeerKeyTrust_RecoveryChainRotates(t *testing.T) {
	old, next := newTrustKey(t), newTrustKey(t)
	chain := []proto.KeyRotationStatement{
		statementFor(t, old, next, trustPeerAccount, proto.KeyRotationReasonRecovery),
	}

	outcome := evaluatePeerKeyTrust(
		verifiedPin(old.fingerprint), trustPeerAccount, next.fingerprint, chain, trustNow,
	)

	if !outcome.Allowed || outcome.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("recovery chain gave allowed=%t state=%q, want an allowed rotation: %s",
			outcome.Allowed, outcome.State, outcome.Reason)
	}
}

func TestEvaluatePeerKeyTrust_MultiLinkChainRotates(t *testing.T) {
	first, second, third := newTrustKey(t), newTrustKey(t), newTrustKey(t)
	chain := []proto.KeyRotationStatement{
		statementFor(t, first, second, trustPeerAccount, proto.KeyRotationReasonVoluntary),
		statementFor(t, second, third, trustPeerAccount, proto.KeyRotationReasonRecovery),
	}

	outcome := evaluatePeerKeyTrust(
		verifiedPin(first.fingerprint), trustPeerAccount, third.fingerprint, chain, trustNow,
	)

	if !outcome.Allowed || outcome.Pin.Fingerprint != third.fingerprint {
		t.Fatalf("two-link chain gave allowed=%t fingerprint=%q: %s",
			outcome.Allowed, outcome.Pin.Fingerprint, outcome.Reason)
	}
	if outcome.Pin.LastRotationFingerprint != first.fingerprint {
		t.Fatalf("last_rotation_fingerprint = %q, want the pinned fingerprint the chain left",
			outcome.Pin.LastRotationFingerprint)
	}
}

// Everything that must land on `changed`. Each case damages exactly one thing
// about an otherwise valid single-link chain.
func TestEvaluatePeerKeyTrust_RefusesUnexplainedChange(t *testing.T) {
	old, next, stranger := newTrustKey(t), newTrustKey(t), newTrustKey(t)
	valid := statementFor(t, old, next, trustPeerAccount, proto.KeyRotationReasonVoluntary)

	damage := func(mutate func(s *proto.KeyRotationStatement)) []proto.KeyRotationStatement {
		broken := valid
		mutate(&broken)
		return []proto.KeyRotationStatement{broken}
	}

	canonicalOther := proto.KeyRotationCanonical(
		trustPeerAccount, old.fingerprint, next.fingerprint, trustRotatedAt+1,
		proto.KeyRotationReasonVoluntary,
	)

	cases := []struct {
		name  string
		chain []proto.KeyRotationStatement
	}{
		{"no chain at all", nil},
		{"empty chain", []proto.KeyRotationStatement{}},
		{
			"chain does not start at the pinned fingerprint",
			[]proto.KeyRotationStatement{statementFor(t, stranger, next, trustPeerAccount, proto.KeyRotationReasonVoluntary)},
		},
		{
			"chain does not end at the observed key",
			[]proto.KeyRotationStatement{statementFor(t, old, stranger, trustPeerAccount, proto.KeyRotationReasonVoluntary)},
		},
		{
			"broken link in the middle",
			[]proto.KeyRotationStatement{
				statementFor(t, old, stranger, trustPeerAccount, proto.KeyRotationReasonVoluntary),
				statementFor(t, newTrustKey(t), next, trustPeerAccount, proto.KeyRotationReasonVoluntary),
			},
		},
		{
			"compromise anywhere in the chain",
			[]proto.KeyRotationStatement{statementFor(t, old, next, trustPeerAccount, proto.KeyRotationReasonCompromise)},
		},
		{
			"statement names a different account",
			[]proto.KeyRotationStatement{statementFor(t, old, next, trustOtherAccount, proto.KeyRotationReasonVoluntary)},
		},
		{
			"old_signature made by a different key",
			damage(func(s *proto.KeyRotationStatement) {
				s.OldSignature = signTrust(t, stranger.priv, s.Canonical())
			}),
		},
		{
			"new_signature made by a different key",
			damage(func(s *proto.KeyRotationStatement) {
				s.NewSignature = signTrust(t, stranger.priv, s.Canonical())
			}),
		},
		{
			"new_signature covers different canonical bytes",
			damage(func(s *proto.KeyRotationStatement) {
				s.NewSignature = signTrust(t, next.priv, canonicalOther)
			}),
		},
		{
			"old_fingerprint does not hash its own old_public_key",
			damage(func(s *proto.KeyRotationStatement) { s.OldPublicKey = stranger.publicB64 }),
		},
		{
			"new_fingerprint does not hash its own new_public_key",
			damage(func(s *proto.KeyRotationStatement) { s.NewPublicKey = stranger.publicB64 }),
		},
		{
			"public key is not Base64",
			damage(func(s *proto.KeyRotationStatement) { s.OldPublicKey = "!!!not base64!!!" }),
		},
		{
			"signature is not Base64",
			damage(func(s *proto.KeyRotationStatement) { s.OldSignature = "!!!not base64!!!" }),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			existing := verifiedPin(old.fingerprint)
			before := *existing

			outcome := evaluatePeerKeyTrust(existing, trustPeerAccount, next.fingerprint, tc.chain, trustNow)

			if outcome.Allowed {
				t.Fatalf("wrap allowed; want refused")
			}
			if outcome.State != keychain.PeerKeyPinStateChanged {
				t.Fatalf("state = %q, want changed", outcome.State)
			}
			if outcome.Reason == "" {
				t.Fatal("refusal carried no reason")
			}
			// The pin the caller handed in must come back untouched: a
			// refusal never lets the observation move the record.
			if *existing != before {
				t.Fatalf("stored pin mutated on refusal: %+v, want %+v", *existing, before)
			}
			if outcome.Pin != (keychain.PeerKeyPin{}) {
				t.Fatalf("refusal handed back a pin to persist: %+v", outcome.Pin)
			}
		})
	}
}
