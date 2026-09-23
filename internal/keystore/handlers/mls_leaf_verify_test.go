// Unit tests for MLSLeafVerifier: design §5.3 over leaves built by hand, so
// every branch runs in the default (no MLS) build. The same rows through real
// MLS — KeyPackages, Commits and Welcomes — are in
// internal/keystore/mls/leaf_verify_e2e_cgo_test.go.
package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	verifyOwner   = "a0000000-0000-4000-8000-000000000001"
	verifyPeer    = "b0000000-0000-4000-8000-000000000002"
	verifyOther   = "c0000000-0000-4000-8000-000000000003"
	verifyDevice  = "d0000000-0000-4000-8000-000000000004"
	verifyDevice2 = "d0000000-0000-4000-8000-000000000005"
	verifyNB      = int64(1758000000)

	// verifyNow sits inside every default declaration window; tests that need
	// a declaration to have expired move the fixture's clock past it.
	verifyNow = verifyNB + 3600
)

// leafSpec is one leaf and the declaration it carries, each field something a
// test can damage on its own.
type leafSpec struct {
	accountID, deviceID string // the credential
	account             trustKey
	leafKey             ed25519.PublicKey

	declAccount, declDevice string
	declKey                 ed25519.PublicKey
	notBefore, notAfter     int64
	reason                  string
	signer                  trustKey // signs the declaration
	carriedPEM              string   // the account key the extension carries
}

func goodLeafSpec(t *testing.T, accountID, deviceID string, account trustKey) leafSpec {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return leafSpec{
		accountID: accountID, deviceID: deviceID, account: account, leafKey: pub,
		declAccount: accountID, declDevice: deviceID, declKey: pub,
		notBefore: verifyNB, notAfter: verifyNB + proto.MLSLeafMaxValiditySeconds,
		reason: proto.MLSLeafReasonEnroll,
		signer: account, carriedPEM: account.pair.PublicKey,
	}
}

func (s leafSpec) declaration(t *testing.T) proto.MLSLeafDeclaration {
	t.Helper()
	fp, err := crypto.MLSLeafSignatureKeyFingerprint(s.declKey)
	if err != nil {
		t.Fatal(err)
	}
	d := proto.MLSLeafDeclaration{
		AccountID:               s.declAccount,
		DeviceID:                s.declDevice,
		SignatureKey:            base64.StdEncoding.EncodeToString(s.declKey),
		SignatureKeyFingerprint: fp,
		NotBefore:               s.notBefore,
		NotAfter:                s.notAfter,
		Reason:                  s.reason,
	}
	d.Signature = signTrust(t, s.signer.priv, d.Canonical())
	return d
}

func (s leafSpec) leaf(t *testing.T) mls.Leaf {
	t.Helper()
	payload, err := proto.EncodeMLSLeafExtension(s.declaration(t), s.carriedPEM)
	if err != nil {
		t.Fatal(err)
	}
	return mls.Leaf{
		Identity:     mls.CredentialIdentity(s.accountID, s.deviceID),
		SignatureKey: s.leafKey,
		Declaration:  payload,
		Entering:     true,
	}
}

type verifyFixture struct {
	deps  Deps
	store keychain.SecretStore
	owner trustKey
	now   *int64
}

func newVerifyFixture(t *testing.T) verifyFixture {
	t.Helper()
	deps, _, store := newTestDeps(t)
	now := verifyNow
	deps.Clock = func() time.Time { return time.Unix(now, 0) }
	owner := newTrustKey(t)
	if err := keychain.SavePublicKey(store, owner.pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	return verifyFixture{deps: deps, store: store, owner: owner, now: &now}
}

func (f verifyFixture) verifier() *MLSLeafVerifier {
	return NewMLSLeafVerifier(f.deps, verifyOwner, nil)
}

func (f verifyFixture) pin(t *testing.T, accountID string) (keychain.PeerKeyPin, bool) {
	t.Helper()
	pin, err := keychain.GetPeerKeyPin(f.store, verifyOwner, accountID)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return keychain.PeerKeyPin{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return pin, true
}

func (f verifyFixture) newest(t *testing.T, accountID string) (keychain.MLSLeafNewest, bool) {
	t.Helper()
	rec, found, err := keychain.GetMLSLeafNewest(f.store, verifyOwner, accountID)
	if err != nil {
		t.Fatal(err)
	}
	return rec, found
}

func requireUntrusted(t *testing.T, err error, wantReason string) {
	t.Helper()
	if !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("err = %v; want ErrLeafUntrusted", err)
	}
	if wantReason != "" && !strings.Contains(err.Error(), wantReason) {
		t.Fatalf("err = %v; want a reason containing %q", err, wantReason)
	}
}

func TestMLSLeafVerifier_FirstContactPinsOnlyAtCommit(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	v := f.verifier()

	if err := v.VerifyLeaves([]mls.Leaf{goodLeafSpec(t, verifyPeer, verifyDevice, peer).leaf(t)}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, found := f.pin(t, verifyPeer); found {
		t.Fatal("a pin was written before the operation succeeded")
	}
	if _, found := f.newest(t, verifyPeer); found {
		t.Fatal("a newest-declaration record was written before the operation succeeded")
	}

	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	pin, found := f.pin(t, verifyPeer)
	if !found || pin.State != keychain.PeerKeyPinStateTOFU || pin.Fingerprint != peer.fingerprint {
		t.Fatalf("pin = %+v, %v; want tofu on the carried key", pin, found)
	}
	if rec, found := f.newest(t, verifyPeer); !found || rec.NotBefore != verifyNB {
		t.Fatalf("newest = %+v, %v", rec, found)
	}
}

// Design §11 V3 A1–A5 and the other §5.3 refusals, one damaged field each.
func TestMLSLeafVerifier_RefusesEveryUntrustedLeafAndStagesNothing(t *testing.T) {
	peer, other := newTrustKey(t), newTrustKey(t)
	otherKey, _, _ := ed25519.GenerateKey(nil)

	appendToPayload := func(extra string) func(*mls.Leaf) {
		return func(l *mls.Leaf) {
			l.Declaration = append(l.Declaration[:len(l.Declaration)-1], []byte(extra+"}")...)
		}
	}
	cases := map[string]struct {
		spec   func(*leafSpec)
		leaf   func(*mls.Leaf)
		reason string
	}{
		"A1 no declaration": {leaf: func(l *mls.Leaf) { l.Declaration = nil }, reason: "no leaf declaration"},
		"A2 forged signature": {spec: func(s *leafSpec) { s.signer = other },
			reason: "signature does not verify"},
		"A3 another account's declaration": {spec: func(s *leafSpec) {
			s.declAccount, s.signer, s.carriedPEM = verifyOther, other, other.pair.PublicKey
		}, reason: "different account or device"},
		"A5 unknown reason": {spec: func(s *leafSpec) { s.reason = "revoke" }, reason: "malformed"},
		"another device": {spec: func(s *leafSpec) { s.declDevice = verifyDevice2 },
			reason: "different account or device"},
		"a declaration for another key": {spec: func(s *leafSpec) { s.declKey = otherKey },
			reason: "different signature key"},
		"a credential that is not a device identity": {
			leaf: func(l *mls.Leaf) { l.Identity = []byte("bob@device-1") }, reason: "not a dragpass device identity"},
		"an empty extension": {leaf: func(l *mls.Leaf) { l.Declaration = []byte{} }, reason: "malformed"},
		"an unknown field":   {leaf: appendToPayload(`,"pending":true`), reason: "malformed"},
		"a duplicate key":    {leaf: appendToPayload(`,"v":1`), reason: "malformed"},
		"an oversized extension": {leaf: func(l *mls.Leaf) {
			l.Declaration = make([]byte, proto.MLSLeafExtensionMaxBytes+1)
		}, reason: "malformed"},
		"an unreadable account key": {spec: func(s *leafSpec) { s.carriedPEM = "not a key" },
			reason: "unreadable account key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVerifyFixture(t)
			spec := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
			if tc.spec != nil {
				tc.spec(&spec)
			}
			leaf := spec.leaf(t)
			if tc.leaf != nil {
				tc.leaf(&leaf)
			}

			v := f.verifier()
			requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{leaf}), tc.reason)
			if err := v.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, found := f.pin(t, verifyPeer); found {
				t.Fatal("a refused leaf left a pin")
			}
			if _, found := f.newest(t, verifyPeer); found {
				t.Fatal("a refused leaf left a newest-declaration record")
			}
		})
	}
}

// A4: a pinned account whose leaf carries a different account key, with no
// chain to explain it, is `changed` — refused, both fingerprints reported, the
// pin untouched.
func TestMLSLeafVerifier_AChangedAccountKeyStopsEverything(t *testing.T) {
	f := newVerifyFixture(t)
	peer, swapped := newTrustKey(t), newTrustKey(t)
	pinned := keychain.PeerKeyPin{
		V: keychain.PeerKeyPinVersion, Fingerprint: peer.fingerprint,
		State: keychain.PeerKeyPinStateVerified, FirstSeenAt: 1, LastSeenAt: 1, VerifiedAt: 1,
	}
	if err := keychain.SavePeerKeyPin(f.store, verifyOwner, verifyPeer, pinned); err != nil {
		t.Fatal(err)
	}

	spec := goodLeafSpec(t, verifyPeer, verifyDevice, swapped)
	v := f.verifier()
	err := v.VerifyLeaves([]mls.Leaf{spec.leaf(t)})
	requireUntrusted(t, err, "changed")
	var detail *MLSLeafUntrustedError
	if !errors.As(err, &detail) || detail.ObservedFingerprint != swapped.fingerprint ||
		detail.PinnedFingerprint != peer.fingerprint {
		t.Fatalf("refusal = %+v; want both fingerprints", detail)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if pin, _ := f.pin(t, verifyPeer); pin != pinned {
		t.Fatalf("pin moved to %+v", pin)
	}
}

func TestMLSLeafVerifier_AChainTheEvaluatorAcceptsRotatesAndACompromiseDoesNot(t *testing.T) {
	peer, next := newTrustKey(t), newTrustKey(t)
	for _, tc := range []struct {
		reason string
		ok     bool
	}{
		{proto.KeyRotationReasonVoluntary, true},
		{proto.KeyRotationReasonCompromise, false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			f := newVerifyFixture(t)
			if err := keychain.SavePeerKeyPin(f.store, verifyOwner, verifyPeer, keychain.PeerKeyPin{
				V: keychain.PeerKeyPinVersion, Fingerprint: peer.fingerprint,
				State: keychain.PeerKeyPinStateTOFU, FirstSeenAt: 1, LastSeenAt: 1,
			}); err != nil {
				t.Fatal(err)
			}
			chain := map[string][]proto.KeyRotationStatement{
				verifyPeer: {statementFor(t, peer, next, verifyPeer, tc.reason)},
			}
			v := NewMLSLeafVerifier(f.deps, verifyOwner, chain)
			err := v.VerifyLeaves([]mls.Leaf{goodLeafSpec(t, verifyPeer, verifyDevice, next).leaf(t)})
			if !tc.ok {
				requireUntrusted(t, err, "compromise")
				return
			}
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := v.Commit(); err != nil {
				t.Fatal(err)
			}
			if pin, _ := f.pin(t, verifyPeer); pin.State != keychain.PeerKeyPinStateRotated ||
				pin.Fingerprint != next.fingerprint {
				t.Fatalf("pin = %+v; want rotated to the new key", pin)
			}
		})
	}
}

// All or nothing: a good leaf next to a bad one records nothing either.
func TestMLSLeafVerifier_OneBadLeafStagesNothingForTheGoodOne(t *testing.T) {
	f := newVerifyFixture(t)
	good := goodLeafSpec(t, verifyPeer, verifyDevice, newTrustKey(t)).leaf(t)
	bad := goodLeafSpec(t, verifyOther, verifyDevice, newTrustKey(t)).leaf(t)
	bad.Declaration = nil

	v := f.verifier()
	requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{good, bad}), "")
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, found := f.pin(t, verifyPeer); found {
		t.Fatal("the good leaf was pinned although its batch was refused")
	}
	if _, found := f.newest(t, verifyPeer); found {
		t.Fatal("the good leaf's declaration was recorded although its batch was refused")
	}
}

// This owner's own devices are judged against the key this Keeper holds.
func TestMLSLeafVerifier_OwnLeavesAreJudgedAgainstTheLocalAccountKey(t *testing.T) {
	f := newVerifyFixture(t)
	if err := f.verifier().VerifyLeaves([]mls.Leaf{goodLeafSpec(t, verifyOwner, verifyDevice, f.owner).leaf(t)}); err != nil {
		t.Fatalf("own leaf: %v", err)
	}
	impostor := goodLeafSpec(t, verifyOwner, verifyDevice2, newTrustKey(t)).leaf(t)
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{impostor}), "different account key")
	if _, found := f.pin(t, verifyOwner); found {
		t.Fatal("a pin was kept for this owner's own account")
	}
}

// ─── the newest accepted declaration per account ──────────────────────────

func acceptLeaf(t *testing.T, f verifyFixture, leaf mls.Leaf) {
	t.Helper()
	v := f.verifier()
	if err := v.VerifyLeaves([]mls.Leaf{leaf}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestMLSLeafVerifier_AnOlderDeclarationAfterANewerOneIsRefused(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	old := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer.notBefore, newer.reason = verifyNB+60, proto.MLSLeafReasonRotate

	acceptLeaf(t, f, newer.leaf(t))
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{old.leaf(t)}), "older than one already accepted")
	if rec, _ := f.newest(t, verifyPeer); rec.NotBefore != newer.notBefore {
		t.Fatalf("newest moved to %+v", rec)
	}
}

// Order does not matter inside one batch: an older declaration next to a
// newer one is refused even when it comes first.
func TestMLSLeafVerifier_AnOlderDeclarationInTheSameBatchIsRefused(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	old := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer := goodLeafSpec(t, verifyPeer, verifyDevice2, peer)
	newer.notBefore = verifyNB + 60

	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{old.leaf(t), newer.leaf(t)}), "older")
}

func TestMLSLeafVerifier_EqualNotBeforeWithADifferentKeyIsRefused(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	first := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	acceptLeaf(t, f, first.leaf(t))

	second := goodLeafSpec(t, verifyPeer, verifyDevice, peer) // a fresh leaf key, same not_before
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{second.leaf(t)}), "same not_before")

	// The declaration already accepted still passes: same not_before, same key.
	if err := f.verifier().VerifyLeaves([]mls.Leaf{first.leaf(t)}); err != nil {
		t.Fatalf("re-observing the accepted declaration: %v", err)
	}
}

func TestMLSLeafVerifier_ARefusedOperationDoesNotAdvanceTheRecord(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	acceptLeaf(t, f, goodLeafSpec(t, verifyPeer, verifyDevice, peer).leaf(t))

	newer := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer.notBefore = verifyNB + 60
	bad := goodLeafSpec(t, verifyOther, verifyDevice, newTrustKey(t)).leaf(t)
	bad.Declaration = nil

	v := f.verifier()
	requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{newer.leaf(t), bad}), "")
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.newest(t, verifyPeer); rec.NotBefore != verifyNB {
		t.Fatalf("a refused operation advanced the record to %+v", rec)
	}
}

// The payload the Keeper produces is the payload the verifier parses, and the
// two bounds that describe it are one number.
func TestMLSLeafExtension_BoundsAgree(t *testing.T) {
	if proto.MLSLeafExtensionMaxBytes != keychain.MLSLeafDeclarationMaxBytes {
		t.Fatalf("extension bound %d != keychain bound %d",
			proto.MLSLeafExtensionMaxBytes, keychain.MLSLeafDeclarationMaxBytes)
	}
	if proto.MLSKeyPackageGenerateMaxCount != mls.MaxKeyPackagesPerCall {
		t.Fatalf("request bound %d != session bound %d",
			proto.MLSKeyPackageGenerateMaxCount, mls.MaxKeyPackagesPerCall)
	}
}

// A leaf a Welcome's tree already holds gets the binding checks and no
// freshness check: a member who rotated still sits in older groups under the
// old leaf. It does not move the record either way.
func TestMLSLeafVerifier_AnOlderLeafAlreadyInTheTreeIsNotAFreshnessRefusal(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	old := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer.notBefore = verifyNB + 60
	acceptLeaf(t, f, newer.leaf(t))

	present := old.leaf(t)
	present.Entering = false
	v := f.verifier()
	if err := v.VerifyLeaves([]mls.Leaf{present}); err != nil {
		t.Fatalf("an older leaf already in the tree was refused: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.newest(t, verifyPeer); rec.NotBefore != newer.notBefore {
		t.Fatalf("a present leaf moved the record to %+v", rec)
	}

	// The binding checks still apply to it.
	forged := old
	forged.signer = newTrustKey(t)
	bad := forged.leaf(t)
	bad.Entering = false
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{bad}), "signature does not verify")

	// And the same declaration entering is refused.
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{old.leaf(t)}), "older")
}

func TestMLSLeafVerifier_APresentLeafDoesNotCreateTheRecord(t *testing.T) {
	f := newVerifyFixture(t)
	present := goodLeafSpec(t, verifyPeer, verifyDevice, newTrustKey(t)).leaf(t)
	present.Entering = false
	acceptLeaf(t, f, present)
	if _, found := f.newest(t, verifyPeer); found {
		t.Fatal("a leaf already in a tree created a newest-declaration record")
	}
	if _, found := f.pin(t, verifyPeer); !found {
		t.Fatal("the binding checks' first-use pin was not written")
	}
}

// Expiry is a freshness check: it refuses a declaration whose not_after has
// passed on a leaf that is entering, from the second not_after names.
func TestMLSLeafVerifier_AnExpiredDeclarationCannotEnter(t *testing.T) {
	f := newVerifyFixture(t)
	spec := goodLeafSpec(t, verifyPeer, verifyDevice, newTrustKey(t))

	*f.now = spec.notAfter - 1
	if err := f.verifier().VerifyLeaves([]mls.Leaf{spec.leaf(t)}); err != nil {
		t.Fatalf("a declaration one second before not_after was refused: %v", err)
	}
	for _, at := range []int64{spec.notAfter, spec.notAfter + 86400} {
		*f.now = at
		v := f.verifier()
		requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{spec.leaf(t)}), "expired")
		if err := v.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, found := f.pin(t, verifyPeer); found {
		t.Fatal("a refused expired leaf wrote a pin")
	}
}

// A group older than the 30-day window stays joinable: every leaf of a
// Welcome's tree may carry a declaration that has since expired, and none of
// them is entering.
func TestMLSLeafVerifier_AGroupOlderThanTheWindowStaysJoinable(t *testing.T) {
	f := newVerifyFixture(t)
	peer, third := newTrustKey(t), newTrustKey(t)
	tree := []mls.Leaf{
		goodLeafSpec(t, verifyPeer, verifyDevice, peer).leaf(t),
		goodLeafSpec(t, verifyOther, verifyDevice2, third).leaf(t),
	}
	for i := range tree {
		tree[i].Entering = false
	}
	*f.now = verifyNB + 3*proto.MLSLeafMaxValiditySeconds

	v := f.verifier()
	if err := v.VerifyLeaves(tree); err != nil {
		t.Fatalf("a Welcome whose tree is older than the window was refused: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
}

func treeLeaf(t *testing.T, s leafSpec) mls.Leaf {
	t.Helper()
	l := s.leaf(t)
	l.Entering = false
	return l
}

// A tree leaf under a superseded declaration is accepted up to and including
// MLSLeafTreeGraceSeconds after this owner first saw the newer one, and
// refused from the second after, all or nothing and without touching the record.
func TestMLSLeafVerifier_AStaleTreeLeafIsRefusedOnceTheGracePeriodHasPassed(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	old := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer.notBefore, newer.reason = verifyNB+60, proto.MLSLeafReasonRotate
	sameNotBefore := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	sameNotBefore.notBefore = newer.notBefore // a different key at the record's not_before
	acceptLeaf(t, f, newer.leaf(t))
	before, _ := f.newest(t, verifyPeer)
	if before.FirstSeenAt != verifyNow {
		t.Fatalf("first_seen_at = %d; want the clock when the record advanced (%d)", before.FirstSeenAt, verifyNow)
	}

	for _, stale := range []leafSpec{old, sameNotBefore} {
		*f.now = verifyNow + proto.MLSLeafTreeGraceSeconds
		acceptLeaf(t, f, treeLeaf(t, stale))

		*f.now = verifyNow + proto.MLSLeafTreeGraceSeconds + 1
		bystander := goodLeafSpec(t, verifyOther, verifyDevice2, newTrustKey(t))
		v := f.verifier()
		requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{treeLeaf(t, bystander), treeLeaf(t, stale)}), "grace period")
		if err := v.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, found := f.pin(t, verifyOther); found {
			t.Fatal("a refused Welcome pinned the other member")
		}
		if _, found := f.newest(t, verifyOther); found {
			t.Fatal("a refused Welcome wrote a record")
		}
	}
	if rec, _ := f.newest(t, verifyPeer); rec != before {
		t.Fatalf("record = %+v; want %+v unchanged", rec, before)
	}
}

// Past the grace period a tree leaf that is the recorded declaration, or newer
// than it, still passes, and neither moves the record nor its first_seen_at.
func TestMLSLeafVerifier_ACurrentOrNewerTreeLeafIsUnaffectedByTheGracePeriod(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	current := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	acceptLeaf(t, f, current.leaf(t))
	before, _ := f.newest(t, verifyPeer)

	newer := goodLeafSpec(t, verifyPeer, verifyDevice2, peer)
	newer.notBefore = verifyNB + 60
	*f.now = verifyNow + 10*proto.MLSLeafTreeGraceSeconds
	acceptLeaf(t, f, treeLeaf(t, current))
	acceptLeaf(t, f, treeLeaf(t, newer))
	if rec, _ := f.newest(t, verifyPeer); rec != before {
		t.Fatalf("a tree leaf moved the record to %+v; want %+v", rec, before)
	}
}

// Seeing the recorded declaration again on an entering leaf keeps first_seen_at.
func TestMLSLeafVerifier_FirstSeenAtStaysWhenTheSameDeclarationEntersAgain(t *testing.T) {
	f := newVerifyFixture(t)
	spec := goodLeafSpec(t, verifyPeer, verifyDevice, newTrustKey(t))
	acceptLeaf(t, f, spec.leaf(t))
	*f.now = verifyNow + 3600
	acceptLeaf(t, f, spec.leaf(t))
	if rec, _ := f.newest(t, verifyPeer); rec.FirstSeenAt != verifyNow {
		t.Fatalf("first_seen_at = %d; want %d", rec.FirstSeenAt, verifyNow)
	}
}

// A record 0.0.44–0.0.47 wrote has no first_seen_at. The first read takes it
// as seen now, refuses nothing, and writes that time back, which is what makes
// the grace period end.
func TestMLSLeafVerifier_ALegacyRecordStartsTheGracePeriodOnFirstRead(t *testing.T) {
	f := newVerifyFixture(t)
	peer := newTrustKey(t)
	old := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer := goodLeafSpec(t, verifyPeer, verifyDevice, peer)
	newer.notBefore = verifyNB + 60
	fp, err := crypto.MLSLeafSignatureKeyFingerprint(newer.declKey)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"v":1,"not_before":` + strconv.FormatInt(newer.notBefore, 10) + `,"fingerprint":"` + fp + `"}`
	if err := f.store.Set(config.Service, keychain.MLSLeafNewestAccount(verifyOwner, verifyPeer), legacy); err != nil {
		t.Fatal(err)
	}

	upgradedAt := verifyNow + 100*proto.MLSLeafTreeGraceSeconds
	*f.now = upgradedAt
	acceptLeaf(t, f, treeLeaf(t, old))
	rec, _ := f.newest(t, verifyPeer)
	if rec.V != keychain.MLSLeafNewestVersion || rec.FirstSeenAt != upgradedAt ||
		rec.NotBefore != newer.notBefore || rec.Fingerprint != fp {
		t.Fatalf("record after the first read = %+v; want the same declaration first seen at %d", rec, upgradedAt)
	}

	*f.now = upgradedAt + proto.MLSLeafTreeGraceSeconds
	acceptLeaf(t, f, treeLeaf(t, old))
	*f.now = upgradedAt + proto.MLSLeafTreeGraceSeconds + 1
	requireUntrusted(t, f.verifier().VerifyLeaves([]mls.Leaf{treeLeaf(t, old)}), "grace period")
}

// A refused operation does not backfill a legacy record either.
func TestMLSLeafVerifier_ARefusedOperationDoesNotBackfillALegacyRecord(t *testing.T) {
	f := newVerifyFixture(t)
	spec := goodLeafSpec(t, verifyPeer, verifyDevice, newTrustKey(t))
	fp, err := crypto.MLSLeafSignatureKeyFingerprint(spec.declKey)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `{"v":1,"not_before":` + strconv.FormatInt(spec.notBefore, 10) + `,"fingerprint":"` + fp + `"}`
	if err := f.store.Set(config.Service, keychain.MLSLeafNewestAccount(verifyOwner, verifyPeer), legacy); err != nil {
		t.Fatal(err)
	}
	bad := goodLeafSpec(t, verifyOther, verifyDevice2, newTrustKey(t)).leaf(t)
	bad.Declaration = nil

	v := f.verifier()
	requireUntrusted(t, v.VerifyLeaves([]mls.Leaf{treeLeaf(t, spec), bad}), "")
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := f.newest(t, verifyPeer); rec.FirstSeenAt != 0 {
		t.Fatalf("a refused operation backfilled first_seen_at: %+v", rec)
	}
}
