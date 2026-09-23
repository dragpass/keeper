//go:build mls && cgo

// End-to-end §5.3 through real MLS: KeyPackages, Commits and Welcomes built by
// mls-rs, judged by the handlers package's verifier, enforced by the Rust gate,
// and persisted (or not) by chatstate. Design §11 V3 A1–A5 are the rows here.
package mls_test

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const (
	accountA = "a1111111-1111-4111-8111-111111111111"
	accountB = "b2222222-2222-4222-8222-222222222222"
	accountC = "c3333333-3333-4333-8333-333333333333"
	accountM = "e5555555-5555-4555-8555-555555555555" // mallory
	accountV = "f6666666-6666-4666-8666-666666666666" // a victim whose declaration is replayed
	device1  = "d1111111-1111-4111-8111-111111111111"
	device2  = "d2222222-2222-4222-8222-222222222222"
	conv     = "99999999-9999-4999-8999-999999999999"

	leafNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var noWatermark = chatstate.ServerWatermark{}

// account is one Keeper: a keyring holding an account keypair and, once it
// declares, a leaf key with its declaration.
type account struct {
	id    string
	store *keychain.MemorySecretStore
	deps  handlers.Deps
	pem   string
	priv  *rsa.PrivateKey
}

func newAccount(t testing.TB, id string) *account {
	t.Helper()
	store := keychain.NewMemorySecretStore()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(store, pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.ParsePrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &account{
		id: id, store: store, pem: pair.PublicKey, priv: priv,
		deps: handlers.Deps{
			Logger:            logger.NewMemoryLogger(),
			Store:             store,
			ServerKeyVerifier: verifier.AlwaysOKVerifier{},
		},
	}
}

// declare runs mls_leaf_declare and then mls_leaf_promote on this Keeper, the
// way a device's key becomes the one it signs with, and returns the
// declaration.
func (a *account) declare(t testing.TB, deviceID, reason string, notBefore int64) proto.MLSLeafDeclaration {
	t.Helper()
	d := a.declarePending(t, deviceID, reason, notBefore)
	resp := handlers.HandleMLSLeafPromote(a.deps, proto.MLSLeafPromoteRequest{
		AcceptanceToken: proto.MLSLeafAcceptedToken(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter),
		ServerSignature: "any",
	})
	if !resp.Success {
		t.Fatalf("promote %s: %s", reason, resp.Error)
	}
	return d
}

// declarePending runs mls_leaf_declare alone: the key it mints is pending.
func (a *account) declarePending(t testing.TB, deviceID, reason string, notBefore int64) proto.MLSLeafDeclaration {
	t.Helper()
	req := proto.MLSLeafDeclareRequest{
		ChallengeToken: "dragpass.mls.leaf.challenge|1|" + a.id + "|" + deviceID + "|" + leafNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSLeafChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       a.id,
		DeviceID:        deviceID,
		NotBefore:       notBefore,
		NotAfter:        notBefore + proto.MLSLeafMaxValiditySeconds,
		Reason:          reason,
	}
	resp := handlers.HandleMLSLeafDeclare(a.deps, req)
	if !resp.Success {
		t.Fatalf("declare %s: %s", reason, resp.Error)
	}
	return resp.Data.(proto.MLSLeafDeclareResponseData).MLSLeafDeclaration
}

// device declares (enroll) and opens this Keeper's device session.
func (a *account) device(t testing.TB, deviceID string) *mls.Session {
	t.Helper()
	a.declare(t, deviceID, proto.MLSLeafReasonEnroll, time.Now().Unix())
	return a.session(t)
}

func (a *account) session(t testing.TB) *mls.Session {
	t.Helper()
	s, _, err := mls.NewDeviceSession(a.store)
	if err != nil {
		t.Fatalf("device session: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func (a *account) verifier() *handlers.MLSLeafVerifier {
	return handlers.NewMLSLeafVerifier(a.deps, a.id, nil)
}

func (a *account) sign(t testing.TB, d proto.MLSLeafDeclaration) proto.MLSLeafDeclaration {
	t.Helper()
	sig, err := crypto.SignData(a.priv, d.Canonical())
	if err != nil {
		t.Fatal(err)
	}
	d.Signature = base64.StdEncoding.EncodeToString(sig)
	return d
}

func (a *account) pinOf(t testing.TB, peer string) (keychain.PeerKeyPin, bool) {
	t.Helper()
	pin, err := keychain.GetPeerKeyPin(a.store, a.id, peer)
	if errors.Is(err, keychain.ErrSecretNotFound) {
		return keychain.PeerKeyPin{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return pin, true
}

func (a *account) newestOf(t testing.TB, peer string) (keychain.MLSLeafNewest, bool) {
	t.Helper()
	rec, found, err := keychain.GetMLSLeafNewest(a.store, a.id, peer)
	if err != nil {
		t.Fatal(err)
	}
	return rec, found
}

// forged is a client no Keeper is: its own leaf key, and whatever declaration
// payload the attacker chose (nil for none).
func forged(t testing.TB, accountID, deviceID string, payload func(leafKey ed25519.PublicKey) []byte) *mls.Session {
	t.Helper()
	pub, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := mls.OpenSessionForTest(mls.CredentialIdentity(accountID, deviceID), secret, pub, payload(pub))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func declarationFor(accountID, deviceID string, leafKey ed25519.PublicKey, notBefore int64, reason string) proto.MLSLeafDeclaration {
	fp, _ := crypto.MLSLeafSignatureKeyFingerprint(leafKey)
	return proto.MLSLeafDeclaration{
		AccountID: accountID, DeviceID: deviceID,
		SignatureKey:            base64.StdEncoding.EncodeToString(leafKey),
		SignatureKeyFingerprint: fp, NotBefore: notBefore, NotAfter: notBefore + proto.MLSLeafMaxValiditySeconds,
		Reason: reason,
	}
}

func payload(t testing.TB, d proto.MLSLeafDeclaration, accountPEM string) []byte {
	t.Helper()
	p, err := proto.EncodeMLSLeafExtension(d, accountPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func keyPackage(t testing.TB, s *mls.Session) []byte {
	t.Helper()
	kp, err := s.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// trustAll is a client that does not check anything: how a malicious or
// broken member builds the Commit an honest member then has to refuse.
type trustAll struct{}

func (trustAll) VerifyLeaves([]mls.Leaf) error { return nil }

func openStore(t testing.TB, secrets keychain.SecretStore, owner string) *chatstate.Store {
	t.Helper()
	s, err := chatstate.Open(secrets, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func stateRoot(t *testing.T) {
	t.Helper()
	t.Setenv(chatstate.RootEnvVar, filepath.Join(t.TempDir(), "chat-state"))
}

var commitSeq int

func nextCommitID() string {
	commitSeq++
	return "77777777-7777-4777-8777-" + strconv.FormatInt(int64(700000000000+commitSeq), 10)
}

// groupOf is alice's group persisted in her chat state, and the first peer
// the malicious-attempt cases need already inside it.
type groupOf struct {
	alice      *account
	aliceStore *chatstate.Store
	aliceS     *mls.Session
}

func newGroup(t *testing.T) groupOf {
	t.Helper()
	stateRoot(t)
	alice := newAccount(t, accountA)
	s := alice.device(t, device1)
	if err := s.CreateGroup([]byte(conv)); err != nil {
		t.Fatal(err)
	}
	store := openStore(t, alice.store, alice.id)
	if _, err := mls.Persist(store, conv, noWatermark, s); err != nil {
		t.Fatal(err)
	}
	return groupOf{alice: alice, aliceStore: store, aliceS: s}
}

// add runs one Add through chatstate as alice's Keeper does, with verifier v.
func (g groupOf) add(v mls.LeafVerifier, kps ...[]byte) (chatstate.BeginCommitResult, error) {
	return g.aliceStore.BeginCommit(conv, noWatermark, chatstate.BeginCommitRequest{
		ClientCommitID: nextCommitID(),
		Plan:           chatstate.CommitPlan{AddKeyPackages: kps},
	}, mls.NewCipher(g.aliceS, v))
}

func (g groupOf) confirm(t testing.TB, id string) chatstate.ConfirmCommitResult {
	t.Helper()
	out, err := g.aliceStore.ConfirmCommit(conv, noWatermark,
		chatstate.CommitOutcome{ClientCommitID: id, Kind: chatstate.CommitAccepted}, mls.NewCipher(g.aliceS, trustAll{}))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (g groupOf) storedState(t testing.TB) []byte {
	t.Helper()
	blob, err := g.aliceStore.LoadGroupState(conv, noWatermark)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// untrustedKeyPackages is V3 A1–A5, each a KeyPackage an honest Keeper must
// refuse to Add and must refuse to accept from somebody else's Commit.
// pinned is an account the judging Keeper already holds a pin for; A4 swaps
// its key.
func untrustedKeyPackages(t *testing.T, pinned string) map[string][]byte {
	t.Helper()
	mallory := newAccount(t, accountM)
	victim := newAccount(t, accountV)
	victimDecl := victim.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	now := time.Now().Unix()

	out := map[string][]byte{}

	// A1: the attacker's device, no declaration at all.
	out["A1 no declaration"] = keyPackage(t, forged(t, accountM, device1, func(ed25519.PublicKey) []byte { return nil }))

	// A2: a declaration with a signature the account key never made.
	out["A2 forged signature"] = keyPackage(t, forged(t, accountM, device1, func(k ed25519.PublicKey) []byte {
		d := mallory.sign(t, declarationFor(accountM, device1, k, now, proto.MLSLeafReasonEnroll))
		sig, _ := base64.StdEncoding.DecodeString(d.Signature)
		sig[0] ^= 0xff
		d.Signature = base64.StdEncoding.EncodeToString(sig)
		return payload(t, d, mallory.pem)
	}))

	// A3: another account's genuine declaration served as this account's.
	out["A3 another account's declaration"] = keyPackage(t, forged(t, accountM, device1, func(ed25519.PublicKey) []byte {
		return payload(t, victimDecl, victim.pem)
	}))

	// A4: the pinned account's leaf carries a different account key,
	// genuinely signed by that other key, with no chain.
	swapped := newAccount(t, pinned)
	out["A4 a changed account key"] = keyPackage(t, forged(t, pinned, device2, func(k ed25519.PublicKey) []byte {
		return payload(t, swapped.sign(t, declarationFor(pinned, device2, k, now, proto.MLSLeafReasonEnroll)), swapped.pem)
	}))

	// A5: a correctly signed declaration with a reason nobody defined.
	out["A5 an unknown reason"] = keyPackage(t, forged(t, accountM, device1, func(k ed25519.PublicKey) []byte {
		return payload(t, mallory.sign(t, declarationFor(accountM, device1, k, now, "revoke")), mallory.pem)
	}))

	return out
}

// V3 A1–A5 at the Add: alice's Keeper refuses to build the Commit. Nothing is
// applied, nothing is persisted, no pin is written.
func TestV3_AnHonestKeeperRefusesToAddAnUntrustedLeaf(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bobKP := keyPackage(t, bob.device(t, device1))
	v := g.alice.verifier()
	in, err := g.add(v, bobKP)
	if err != nil {
		t.Fatalf("add bob: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)
	pinB, _ := g.alice.pinOf(t, accountB)

	for name, kp := range untrustedKeyPackages(t, accountB) {
		t.Run(name, func(t *testing.T) {
			before := g.storedState(t)
			v := g.alice.verifier()
			_, err := g.add(v, kp)
			if !errors.Is(err, mls.ErrLeafUntrusted) {
				t.Fatalf("add = %v; want ErrLeafUntrusted", err)
			}
			if err := v.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, pending, err := g.aliceStore.PendingCommit(conv, noWatermark); err != nil || pending {
				t.Fatalf("a refused add left a pending commit: %v, %v", pending, err)
			}
			if string(g.storedState(t)) != string(before) {
				t.Fatal("a refused add changed the stored group state")
			}
			if _, found := g.alice.pinOf(t, accountM); found {
				t.Fatal("a refused add pinned the attacker's account")
			}
			if _, found := g.alice.pinOf(t, accountV); found {
				t.Fatal("a refused add pinned the victim's account")
			}
			if pin, _ := g.alice.pinOf(t, accountB); pin != pinB {
				t.Fatalf("bob's pin moved to %+v", pin)
			}
			var detail *handlers.MLSLeafUntrustedError
			if name == "A4 a changed account key" &&
				(!errors.As(err, &detail) || detail.PinnedFingerprint != crypto.AccountKeyFingerprint([]byte(bob.pem))) {
				t.Fatalf("A4 refusal did not carry the pinned fingerprint: %+v", detail)
			}
		})
	}
}

// memberOf joins a verified member to alice's group and persists its state.
func (g groupOf) memberOf(t *testing.T, a *account, deviceID string) (*mls.Session, *chatstate.Store) {
	t.Helper()
	s := a.device(t, deviceID)
	in, err := g.add(trustAll{}, keyPackage(t, s))
	if err != nil {
		t.Fatal(err)
	}
	out := g.confirm(t, in.ClientCommitID)
	v := a.verifier()
	if err := s.JoinVerified(out.Welcome, v); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	store := openStore(t, a.store, a.id)
	if _, err := mls.Persist(store, conv, noWatermark, s); err != nil {
		t.Fatal(err)
	}
	return s, store
}

// V3 A1–A5 at the receiver: a member that does not check commits an
// untrusted leaf, and bob's Keeper refuses to apply it. Bob pinned alice's
// account when he joined, so A4 swaps hers.
func TestV3_AMemberRefusesACommitThatBringsInAnUntrustedLeaf(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	_, bobStore := g.memberOf(t, bob, device1)
	pinA, found := bob.pinOf(t, accountA)
	if !found {
		t.Fatal("joining did not pin the committer's account")
	}
	if _, err := mls.Restore(g.aliceStore, conv, noWatermark, g.aliceS); err != nil {
		t.Fatal(err)
	}

	seq := uint64(0)
	for name, kp := range untrustedKeyPackages(t, accountA) {
		t.Run(name, func(t *testing.T) {
			commit, _, _, err := g.aliceS.CommitAddMemberVerified(kp, trustAll{})
			if name == "A1 no declaration" {
				// Not even a Keeper whose verifier approves everything can
				// build this one: an approval always names declaration bytes,
				// so the Rust gate has nothing to match a bare leaf against.
				// The receiver half of A1 is session.rs's
				// a_commit_adding_a_leaf_without_a_declaration_is_refused.
				if !errors.Is(err, mls.ErrLeafUntrusted) {
					t.Fatalf("a leaf with no declaration was committed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("the unchecking member could not build the commit: %v", err)
			}
			if err := g.aliceS.ClearPendingCommit(); err != nil {
				t.Fatal(err)
			}

			before, _ := bobStore.LoadGroupState(conv, noWatermark)
			v := bob.verifier()
			seq++
			_, err = bobStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: seq, Message: commit},
				mls.NewCipher(bob.session(t), v))
			if !errors.Is(err, mls.ErrLeafUntrusted) {
				t.Fatalf("receive = %v; want ErrLeafUntrusted", err)
			}
			if err := v.Commit(); err != nil {
				t.Fatal(err)
			}
			after, _ := bobStore.LoadGroupState(conv, noWatermark)
			if string(before) != string(after) {
				t.Fatal("a refused commit changed bob's stored group state")
			}
			for _, peer := range []string{accountM, accountV} {
				if _, found := bob.pinOf(t, peer); found {
					t.Fatalf("a refused commit pinned %s", peer)
				}
			}
			if pin, _ := bob.pinOf(t, accountA); pin.Fingerprint != pinA.Fingerprint {
				t.Fatal("a refused commit moved the pin of the committer's account")
			}
		})
	}
}

// TOFU: an unpinned member verifies from the key its leaf carries, and the pin
// appears only once the whole operation has succeeded — at the Add, and at a
// receiver applying somebody else's Commit.
func TestTOFU_ThePinIsWrittenOnlyAfterTheWholeCommitSucceeds(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	_, bobStore := g.memberOf(t, bob, device1)
	if _, err := mls.Restore(g.aliceStore, conv, noWatermark, g.aliceS); err != nil {
		t.Fatal(err)
	}
	carol := newAccount(t, accountC)
	carolKP := keyPackage(t, carol.device(t, device1))

	// The Add.
	v := g.alice.verifier()
	in, err := g.add(v, carolKP)
	if err != nil {
		t.Fatalf("add carol: %v", err)
	}
	if _, found := g.alice.pinOf(t, accountC); found {
		t.Fatal("alice pinned carol before the operation was reported as done")
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	pin, found := g.alice.pinOf(t, accountC)
	if !found || pin.State != keychain.PeerKeyPinStateTOFU ||
		pin.Fingerprint != crypto.AccountKeyFingerprint([]byte(carol.pem)) {
		t.Fatalf("alice's pin for carol = %+v, %v", pin, found)
	}

	// The receiver.
	bv := bob.verifier()
	if _, err := bobStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: 1, Message: in.Commit},
		mls.NewCipher(bob.session(t), bv)); err != nil {
		t.Fatalf("bob receive: %v", err)
	}
	if _, found := bob.pinOf(t, accountC); found {
		t.Fatal("bob pinned carol before the operation was reported as done")
	}
	if err := bv.Commit(); err != nil {
		t.Fatal(err)
	}
	if pin, found := bob.pinOf(t, accountC); !found || pin.State != keychain.PeerKeyPinStateTOFU {
		t.Fatalf("bob's pin for carol = %+v, %v", pin, found)
	}
	if rec, found := bob.newestOf(t, accountC); !found || rec.NotBefore <= 0 {
		t.Fatalf("bob's newest-declaration record for carol = %+v, %v", rec, found)
	}
}

// All or nothing across one Commit: a good leaf beside a bad one is not
// pinned either, at the Add and at the receiver.
func TestOneGoodAndOneBadLeafWritesNoPinForTheGoodOne(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	_, bobStore := g.memberOf(t, bob, device1)
	if _, err := mls.Restore(g.aliceStore, conv, noWatermark, g.aliceS); err != nil {
		t.Fatal(err)
	}
	carol := newAccount(t, accountC)
	good := keyPackage(t, carol.device(t, device1))
	bad := untrustedKeyPackages(t, accountA)["A2 forged signature"]

	v := g.alice.verifier()
	if _, err := g.add(v, good, bad); !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("add good+bad = %v; want ErrLeafUntrusted", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, found := g.alice.pinOf(t, accountC); found {
		t.Fatal("alice pinned the good member of a refused Commit")
	}
	if _, found := g.alice.newestOf(t, accountC); found {
		t.Fatal("alice recorded the good member's declaration from a refused Commit")
	}

	commit, _, _, err := g.aliceS.CommitAddMembersVerified([][]byte{good, bad}, trustAll{})
	if err != nil {
		t.Fatalf("the unchecking member could not build the commit: %v", err)
	}
	bv := bob.verifier()
	if _, err := bobStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: 1, Message: commit},
		mls.NewCipher(bob.session(t), bv)); !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("bob receive good+bad = %v; want ErrLeafUntrusted", err)
	}
	if err := bv.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, found := bob.pinOf(t, accountC); found {
		t.Fatal("bob pinned the good member of a refused Commit")
	}
}

// A joiner verifies the whole tree. One untrusted leaf that is not the
// committer is enough to refuse the Welcome, and nothing is pinned for the
// honest members either.
func TestAWelcomeWhoseTreeHoldsOneUntrustedLeafIsRefused(t *testing.T) {
	stateRoot(t)
	alice := newAccount(t, accountA)
	aliceS := alice.device(t, device1)
	if err := aliceS.CreateGroup([]byte(conv)); err != nil {
		t.Fatal(err)
	}
	// Alice does not check: mallory's forged leaf goes in first.
	if _, _, _, err := aliceS.CommitAddMemberVerified(
		untrustedKeyPackages(t, accountB)["A2 forged signature"], trustAll{}); err != nil {
		t.Fatal(err)
	}
	if err := aliceS.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}
	dave := newAccount(t, accountC)
	daveS := dave.device(t, device1)
	_, welcome, _, err := aliceS.CommitAddMemberVerified(keyPackage(t, daveS), trustAll{})
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceS.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}

	v := dave.verifier()
	if err := daveS.JoinVerified(welcome, v); !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("join = %v; want ErrLeafUntrusted", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := daveS.Epoch(); err == nil {
		t.Fatal("a refused Welcome left the joiner in a group")
	}
	for _, peer := range []string{accountA, accountM} {
		if _, found := dave.pinOf(t, peer); found {
			t.Fatalf("a refused Welcome pinned %s", peer)
		}
	}
}

// The newest-declaration record through real KeyPackages. A lost device's
// leaf key still produces KeyPackages whose superseded declaration verifies;
// once alice has accepted the newer one, the older is refused. Equal
// not_before with a different key is refused too, and a refused operation
// does not move the record.
func TestASupersededDeclarationIsRefusedOnceANewerOneWasAccepted(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	t0 := time.Now().Unix()
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, t0)
	lost := bob.session(t) // the device that is later lost keeps its old key
	oldKP := keyPackage(t, lost)
	bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+60)
	newKP := keyPackage(t, bob.session(t))

	v := g.alice.verifier()
	in, err := g.add(v, newKP)
	if err != nil {
		t.Fatalf("add the current key: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)
	if rec, _ := g.alice.newestOf(t, accountB); rec.NotBefore != t0+60 {
		t.Fatalf("newest = %+v; want the rotated declaration", rec)
	}

	v = g.alice.verifier()
	if _, err := g.add(v, oldKP); !errors.Is(err, mls.ErrLeafUntrusted) ||
		!strings.Contains(err.Error(), "older than one already accepted") {
		t.Fatalf("add the superseded key = %v; want ErrLeafUntrusted for an older declaration", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}

	// Same not_before as the accepted declaration, another key.
	bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+60)
	twin := keyPackage(t, bob.session(t))
	if _, err := g.add(g.alice.verifier(), twin); !errors.Is(err, mls.ErrLeafUntrusted) ||
		!strings.Contains(err.Error(), "same not_before") {
		t.Fatalf("add an equal-not_before twin = %v; want ErrLeafUntrusted for two current keys", err)
	}

	// A newer declaration inside a refused Commit does not advance the record.
	bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+120)
	newest := keyPackage(t, bob.session(t))
	bad := untrustedKeyPackages(t, accountA)["A2 forged signature"]
	v = g.alice.verifier()
	if _, err := g.add(v, newest, bad); !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("add newest+bad = %v; want ErrLeafUntrusted", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := g.alice.newestOf(t, accountB); rec.NotBefore != t0+60 {
		t.Fatalf("a refused Commit moved the record to %+v", rec)
	}
}

// What a KeyPackage embeds is the stored active declaration, byte for byte,
// and rotate replaces the key and the declaration together.
func TestTheStoredDeclarationIsEmbeddedUnchangedAndRotateReplacesBoth(t *testing.T) {
	stateRoot(t)
	bob := newAccount(t, accountB)
	t0 := time.Now().Unix()
	enrolled := bob.declare(t, device1, proto.MLSLeafReasonEnroll, t0)
	first, _, _ := keychain.GetMLSLeafKey(bob.store)

	s1 := bob.session(t)
	kp1 := keyPackage(t, s1)
	carrier := forged(t, accountA, device1, func(ed25519.PublicKey) []byte { return []byte("x") })
	if err := carrier.CreateGroup([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	spy := &recordLeaves{}
	if _, _, _, err := carrier.CommitAddMemberVerified(kp1, spy); err != nil {
		t.Fatal(err)
	}
	if len(spy.leaves) != 1 || string(spy.leaves[0].Declaration) != string(first.Declaration) ||
		string(spy.leaves[0].SignatureKey) != string(first.PublicKey) {
		t.Fatal("the key package does not carry the stored declaration and key unchanged")
	}
	want, err := proto.EncodeMLSLeafExtension(enrolled, bob.pem)
	if err != nil || string(first.Declaration) != string(want) {
		t.Fatal("the stored declaration is not the one mls_leaf_declare returned")
	}

	rotated := bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+60)
	second, _, _ := keychain.GetMLSLeafKey(bob.store)
	if string(second.PublicKey) == string(first.PublicKey) ||
		string(second.Declaration) == string(first.Declaration) {
		t.Fatal("rotate did not replace both the key and the declaration")
	}
	fp, _ := crypto.MLSLeafSignatureKeyFingerprint(second.PublicKey)
	if rotated.SignatureKeyFingerprint != fp {
		t.Fatal("the rotated declaration does not name the rotated key")
	}
	spy.leaves = nil
	if err := carrier.ClearPendingCommit(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := carrier.CommitAddMemberVerified(keyPackage(t, bob.session(t)), spy); err != nil {
		t.Fatal(err)
	}
	if string(spy.leaves[0].Declaration) != string(second.Declaration) {
		t.Fatal("a key package from the rotated session does not carry the rotated declaration")
	}
}

type recordLeaves struct{ leaves []mls.Leaf }

func (r *recordLeaves) VerifyLeaves(leaves []mls.Leaf) error {
	r.leaves = append(r.leaves, leaves...)
	return nil
}

// The server stores a KeyPackage in VARBINARY(8192). This is the measured
// size of a real one, with an RSA-2048 account key and its PSS signature in
// the extension.
func TestAKeyPackageFitsTheServerColumn(t *testing.T) {
	stateRoot(t)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	stored, _, _ := keychain.GetMLSLeafKey(bob.store)
	for _, kp := range bob.keyPackagesFor(t, device1, 4) {
		t.Logf("key package: %d bytes (declaration extension %d bytes), cap %d",
			len(kp), len(stored.Declaration), mls.MaxKeyPackageBytes)
		if len(kp) > mls.MaxKeyPackageBytes {
			t.Fatalf("key package of %d bytes", len(kp))
		}
	}
}

// Freshness applies only to entering leaves. Bob rotates; his old leaf stays
// in the groups he was already in. Dave has seen bob's newer declaration, and
// can still join such a group from a Welcome — the old leaf is already in the
// tree and gets the binding checks only — while an Add that tries to bring the
// old declaration in is refused. The join leaves dave's record where it was.
func TestAWelcomeTreeHoldingARotatedMembersOldLeafIsStillJoinable(t *testing.T) {
	stateRoot(t)
	bob := newAccount(t, accountB)
	t0 := time.Now().Unix()
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, t0)
	bobOld := bob.session(t)

	// Alice's group, with bob's old leaf in it.
	alice := newAccount(t, accountA)
	aliceS := alice.device(t, device1)
	if err := aliceS.CreateGroup([]byte("older group")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := aliceS.CommitAddMemberVerified(keyPackage(t, bobOld), alice.verifier()); err != nil {
		t.Fatal(err)
	}
	if err := aliceS.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}

	// Bob rotates, and dave accepts the newer declaration in a group of his own.
	bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+60)
	dave := newAccount(t, accountC)
	daveOwn := dave.device(t, device1)
	if err := daveOwn.CreateGroup([]byte("dave's group")); err != nil {
		t.Fatal(err)
	}
	v := dave.verifier()
	if _, _, _, err := daveOwn.CommitAddMemberVerified(keyPackage(t, bob.session(t)), v); err != nil {
		t.Fatalf("dave adds bob's current leaf: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := daveOwn.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := dave.newestOf(t, accountB); rec.NotBefore != t0+60 {
		t.Fatalf("dave's record = %+v; want bob's rotated declaration", rec)
	}

	// Dave joins alice's older group, whose tree holds bob's old leaf.
	daveJoining := dave.session(t)
	_, welcome, _, err := aliceS.CommitAddMemberVerified(keyPackage(t, daveJoining), alice.verifier())
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceS.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}
	v = dave.verifier()
	if err := daveJoining.JoinVerified(welcome, v); err != nil {
		t.Fatalf("dave could not join a group holding bob's older leaf: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if rec, _ := dave.newestOf(t, accountB); rec.NotBefore != t0+60 {
		t.Fatalf("joining moved dave's record to %+v", rec)
	}

	// The same device refuses an Add that brings the old declaration in.
	if _, _, _, err := daveOwn.CommitAddMemberVerified(keyPackage(t, bobOld), dave.verifier()); !errors.Is(err, mls.ErrLeafUntrusted) ||
		!strings.Contains(err.Error(), "older than one already accepted") {
		t.Fatalf("dave adds bob's old leaf = %v; want a refusal for an older declaration", err)
	}
}

// Only the active entry signs. A key mls_leaf_declare minted and ariadne has
// not accepted never reaches a session, a KeyPackage or a group.
func TestAPendingLeafKeyNeverSigns(t *testing.T) {
	stateRoot(t)
	bob := newAccount(t, accountB)
	bob.declarePending(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	if _, _, err := mls.NewDeviceSession(bob.store); !errors.Is(err, mls.ErrNoLeafKey) {
		t.Fatalf("session with only a pending key = %v; want ErrNoLeafKey", err)
	}

	bob2 := newAccount(t, accountC)
	enrolled := bob2.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	staged := bob2.declarePending(t, device1, proto.MLSLeafReasonRotate, time.Now().Unix()+1)
	spy := &recordLeaves{}
	carrier := forged(t, accountA, device1, func(ed25519.PublicKey) []byte { return []byte("x") })
	if err := carrier.CreateGroup([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := carrier.CommitAddMemberVerified(keyPackage(t, bob2.session(t)), spy); err != nil {
		t.Fatal(err)
	}
	want, _ := base64.StdEncoding.DecodeString(enrolled.SignatureKey)
	pending, _ := base64.StdEncoding.DecodeString(staged.SignatureKey)
	if len(spy.leaves) != 1 || string(spy.leaves[0].SignatureKey) != string(want) ||
		string(spy.leaves[0].SignatureKey) == string(pending) {
		t.Fatal("a KeyPackage carried the pending key instead of the active one")
	}
}

// Expiry through real MLS. Bob's KeyPackage carries a declaration whose
// not_after has passed on alice's clock, so she will not Add him; but a group
// whose every declaration has expired is still one a new member can join,
// because nothing in a Welcome's tree is entering.
func TestAnExpiredDeclarationCannotBeAddedButAnOldGroupCanBeJoined(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bobKP := keyPackage(t, bob.device(t, device1))
	later := time.Now().Add(40 * 24 * time.Hour)

	aliceLater := g.alice.deps
	aliceLater.Clock = func() time.Time { return later }
	if _, err := g.add(handlers.NewMLSLeafVerifier(aliceLater, g.alice.id, nil), bobKP); !errors.Is(err, mls.ErrLeafUntrusted) ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("add with an expired declaration = %v; want ErrLeafUntrusted for expiry", err)
	}

	in, err := g.add(g.alice.verifier(), bobKP)
	if err != nil {
		t.Fatalf("add in the window: %v", err)
	}
	g.confirm(t, in.ClientCommitID)
	carol := newAccount(t, accountC)
	carolS := carol.device(t, device2)
	in, err = g.add(g.alice.verifier(), keyPackage(t, carolS))
	if err != nil {
		t.Fatalf("add carol: %v", err)
	}
	g.confirm(t, in.ClientCommitID)

	carolLater := carol.deps
	carolLater.Clock = func() time.Time { return later }
	if err := carolS.JoinVerified(in.Welcome, handlers.NewMLSLeafVerifier(carolLater, carol.id, nil)); err != nil {
		t.Fatalf("joining a group whose declarations have all expired: %v", err)
	}
}

// keyPackagesFor runs mls_key_package_generate on this Keeper: KeyPackages for
// its active leaf, their private keys sealed into its pool.
func (a *account) keyPackagesFor(t testing.TB, deviceID string, count int) [][]byte {
	t.Helper()
	resp := handlers.HandleMLSKeyPackageGenerate(a.deps, proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: "dragpass.mls.keypackage.challenge|1|" + a.id + "|" + deviceID + "|" + leafNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       a.id,
		DeviceID:        deviceID,
		Count:           count,
	})
	if !resp.Success {
		t.Fatalf("key package generate: %s", resp.Error)
	}
	var out [][]byte
	for _, kp := range resp.Data.(proto.MLSKeyPackageGenerateResponseData).KeyPackages {
		raw, err := base64.StdEncoding.DecodeString(kp.KeyPackageB64)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

func poolSize(t testing.TB, store *chatstate.Store) int {
	t.Helper()
	n, err := store.KeyPackagePoolSize(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The gap L2 left: KeyPackages made by one Keeper process, a Welcome joined by
// another. Bob's Keeper generates through the action, a later session joins
// from the pool, the group state lands in his chat state and only then does
// the pool entry go.
func TestAWelcomeToAnUploadedKeyPackageIsJoinedByALaterProcess(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	kps := bob.keyPackagesFor(t, device1, 3)
	bobStore := openStore(t, bob.store, bob.id)
	if n := poolSize(t, bobStore); n != 3 {
		t.Fatalf("pool holds %d, want 3", n)
	}

	in, err := g.add(g.alice.verifier(), kps[1])
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	g.confirm(t, in.ClientCommitID)

	later := bob.session(t) // a process that never saw the KeyPackages made
	v := bob.verifier()
	if err := later.JoinFromPool(bobStore, conv, noWatermark, in.Welcome, v, time.Now()); err != nil {
		t.Fatalf("join from the pool: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	if epoch, err := later.Epoch(); err != nil || epoch != 1 {
		t.Fatalf("epoch = %d, %v", epoch, err)
	}
	if blob, err := bobStore.LoadGroupState(conv, noWatermark); err != nil || len(blob) == 0 {
		t.Fatalf("the joined group was not persisted: %v", err)
	}
	if n := poolSize(t, bobStore); n != 2 {
		t.Fatalf("pool holds %d after the join, want 2", n)
	}

	// The same Welcome again finds nothing: its keys were used and deleted.
	again := bob.session(t)
	if err := again.JoinFromPool(bobStore, conv, noWatermark, in.Welcome, bob.verifier(), time.Now()); !errors.Is(err, mls.ErrNoKeyPackageForWelcome) {
		t.Fatalf("a second join = %v; want ErrNoKeyPackageForWelcome", err)
	}
}

// The ordering: when the group state cannot be written, the pool entry stays,
// so the invitation is not lost with it.
func TestAJoinWhoseGroupStateIsNotWrittenKeepsThePoolEntry(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	kps := bob.keyPackagesFor(t, device1, 1)
	bobStore := openStore(t, bob.store, bob.id)
	in, err := g.add(g.alice.verifier(), kps[0])
	if err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)

	// A server watermark ahead of a conversation this device has never
	// written is refused as a rewind, so the group state write fails.
	ahead := chatstate.ServerWatermark{Epoch: 5, NextApplicationIndex: 5}
	if err := bob.session(t).JoinFromPool(bobStore, conv, ahead, in.Welcome, bob.verifier(), time.Now()); err == nil {
		t.Fatal("the join succeeded although its group state could not be written")
	}
	if n := poolSize(t, bobStore); n != 1 {
		t.Fatalf("pool holds %d after a failed write, want the entry kept", n)
	}
}

// invite builds a group holding the members' leaves, as a committer who checks
// nothing would: what the joiner makes of the tree is what is under test.
func invite(t testing.TB, host *account, groupID string, members ...[]byte) (*mls.Session, func(kp []byte) []byte) {
	t.Helper()
	s := host.session(t)
	if err := s.CreateGroup([]byte(groupID)); err != nil {
		t.Fatal(err)
	}
	add := func(kp []byte) []byte {
		_, welcome, _, err := s.CommitAddMemberVerified(kp, trustAll{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ApplyPendingCommit(); err != nil {
			t.Fatal(err)
		}
		return welcome
	}
	for _, kp := range members {
		add(kp)
	}
	return s, add
}

// staleTreeScenario: bob's old leaf sits in alice's older group; bob rotates,
// and dave accepts the newer declaration in a group of his own at a clock the
// test controls. Dave has KeyPackages in his pool for the joins that follow.
type staleTreeScenario struct {
	t0         int64
	bob, dave  *account
	daveStore  *chatstate.Store
	daveKPs    [][]byte
	clock      *int64
	firstSeen  int64
	olderGroup func(kp []byte) []byte
}

func newStaleTreeScenario(t *testing.T) staleTreeScenario {
	t.Helper()
	stateRoot(t)
	bob := newAccount(t, accountB)
	t0 := time.Now().Unix()
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, t0)
	alice := newAccount(t, accountA)
	alice.device(t, device1)
	_, olderGroup := invite(t, alice, "older group", keyPackage(t, bob.session(t)))

	bob.declare(t, device1, proto.MLSLeafReasonRotate, t0+60)
	dave := newAccount(t, accountC)
	daveOwn := dave.device(t, device1)
	daveKPs := dave.keyPackagesFor(t, device1, 4)
	daveStore := openStore(t, dave.store, dave.id)

	clock := time.Now().Unix()
	dave.deps.Clock = func() time.Time { return time.Unix(clock, 0) }
	if err := daveOwn.CreateGroup([]byte("dave's group")); err != nil {
		t.Fatal(err)
	}
	v := dave.verifier()
	if _, _, _, err := daveOwn.CommitAddMemberVerified(keyPackage(t, bob.session(t)), v); err != nil {
		t.Fatalf("dave adds bob's current leaf: %v", err)
	}
	if err := v.Commit(); err != nil {
		t.Fatal(err)
	}
	rec, _ := dave.newestOf(t, accountB)
	if rec.NotBefore != t0+60 || rec.FirstSeenAt != clock {
		t.Fatalf("dave's record = %+v; want bob's rotated declaration first seen at %d", rec, clock)
	}
	return staleTreeScenario{
		t0: t0, bob: bob, dave: dave, daveStore: daveStore, daveKPs: daveKPs,
		clock: &clock, firstSeen: clock, olderGroup: olderGroup,
	}
}

func (s staleTreeScenario) join(t *testing.T, conversationID string, welcome []byte) error {
	t.Helper()
	v := s.dave.verifier()
	if err := s.dave.session(t).JoinFromPool(s.daveStore, conversationID, noWatermark, welcome, v, time.Now()); err != nil {
		return err
	}
	return v.Commit()
}

const (
	convGrace1 = "99999999-9999-4999-8999-000000000001"
	convGrace2 = "99999999-9999-4999-8999-000000000002"
	convGrace3 = "99999999-9999-4999-8999-000000000003"
	convGrace4 = "99999999-9999-4999-8999-000000000004"
)

// P3. Up to MLSLeafTreeGraceSeconds after dave first saw bob's rotation, a
// group whose tree still holds bob's old leaf is joinable, and the join does
// not touch dave's record.
func TestAStaleTreeLeafIsJoinableWithinTheGracePeriod(t *testing.T) {
	s := newStaleTreeScenario(t)
	before, _ := s.dave.newestOf(t, accountB)

	*s.clock = s.firstSeen + proto.MLSLeafTreeGraceSeconds
	if err := s.join(t, convGrace1, s.olderGroup(s.daveKPs[0])); err != nil {
		t.Fatalf("join at the end of the grace period: %v", err)
	}
	if rec, _ := s.dave.newestOf(t, accountB); rec != before {
		t.Fatalf("joining moved dave's record to %+v; want %+v", rec, before)
	}
	if blob, err := s.daveStore.LoadGroupState(convGrace1, noWatermark); err != nil || len(blob) == 0 {
		t.Fatalf("the joined group was not persisted: %v", err)
	}
}

// P3. One second later the same kind of Welcome is refused, all or nothing: no
// group state, the pool entry kept, no pin for the members, the record as it
// was. A tree holding bob's current leaf, or one newer than dave has seen, is
// still joinable and moves nothing.
func TestAStaleTreeLeafIsRefusedOnceTheGracePeriodHasPassed(t *testing.T) {
	s := newStaleTreeScenario(t)
	before, _ := s.dave.newestOf(t, accountB)
	poolBefore := poolSize(t, s.daveStore)

	*s.clock = s.firstSeen + proto.MLSLeafTreeGraceSeconds + 1
	err := s.join(t, convGrace2, s.olderGroup(s.daveKPs[1]))
	if !errors.Is(err, mls.ErrLeafUntrusted) || !strings.Contains(err.Error(), "grace period") {
		t.Fatalf("join past the grace period = %v; want ErrLeafUntrusted for a superseded tree leaf", err)
	}
	if blob, err := s.daveStore.LoadGroupState(convGrace2, noWatermark); err != nil || len(blob) != 0 {
		t.Fatalf("a refused Welcome persisted a group (%d bytes, %v)", len(blob), err)
	}
	if n := poolSize(t, s.daveStore); n != poolBefore {
		t.Fatalf("pool holds %d after a refused join, want %d", n, poolBefore)
	}
	if _, found := s.dave.pinOf(t, accountA); found {
		t.Fatal("a refused Welcome pinned its committer")
	}
	if rec, _ := s.dave.newestOf(t, accountB); rec != before {
		t.Fatalf("a refused Welcome moved dave's record to %+v", rec)
	}

	alice := newAccount(t, accountA)
	alice.device(t, device1)
	_, current := invite(t, alice, "current group", keyPackage(t, s.bob.session(t)))
	if err := s.join(t, convGrace3, current(s.daveKPs[2])); err != nil {
		t.Fatalf("joining a tree holding bob's current leaf: %v", err)
	}

	s.bob.declare(t, device1, proto.MLSLeafReasonRotate, s.t0+120)
	_, newer := invite(t, alice, "newer group", keyPackage(t, s.bob.session(t)))
	if err := s.join(t, convGrace4, newer(s.daveKPs[3])); err != nil {
		t.Fatalf("joining a tree holding a leaf newer than dave's record: %v", err)
	}
	if rec, _ := s.dave.newestOf(t, accountB); rec != before {
		t.Fatalf("tree leaves moved dave's record to %+v; want %+v", rec, before)
	}
}
