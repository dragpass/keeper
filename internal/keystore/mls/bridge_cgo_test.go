//go:build mls && cgo

package mls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

const (
	testOwner = "11111111-1111-4111-8111-111111111111"
	testConv  = "22222222-2222-4222-8222-222222222222"
)

// trustAll stands in for the handlers package's verifier in tests about
// something other than leaf trust. It approves whatever the collect pass
// reports, so the Rust gate still runs; the §5.3 checks themselves are tested
// through real declarations in the handlers package.
type trustAll struct{}

func (trustAll) VerifyLeaves([]Leaf) error { return nil }
func (trustAll) Commit() error             { return nil }

func newSession(t testing.TB, identity string) *Session {
	t.Helper()
	secret, public, err := generateSignatureKey()
	if err != nil {
		t.Fatalf("generate signature key: %v", err)
	}
	s, err := openSession(testIdentity(identity), secret, public, []byte("test declaration of "+identity))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// testIdentity gives a named test member a DragPass device identity, the only
// kind Cipher.Open can name as the sender of a message. The ids are derived
// from the name so a restored session is the same member.
func testIdentity(name string) []byte {
	sum := sha256.Sum256([]byte(name))
	h := hex.EncodeToString(sum[:])
	uuid := func(x string) string {
		return x[0:8] + "-" + x[8:12] + "-4" + x[13:16] + "-8" + x[17:20] + "-" + x[20:32]
	}
	return CredentialIdentity(uuid(h[:32]), uuid(h[32:]))
}

// twoMemberGroup returns alice (the creator), bob (joined via Welcome) and the
// commit alice produced, so tests can assert on the wire form of real output.
func twoMemberGroup(t testing.TB) (alice, bob *Session, commit []byte) {
	t.Helper()
	alice = newSession(t, "alice@device-1")
	bob = newSession(t, "bob@device-1")

	if err := alice.CreateGroup([]byte("conversation-under-test")); err != nil {
		t.Fatalf("create group: %v", err)
	}
	kp, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("key package: %v", err)
	}
	commit, welcome, _, err := alice.CommitAddMemberVerified(kp, trustAll{})
	if err != nil {
		t.Fatalf("commit add member: %v", err)
	}
	// Building it did not move alice. In the real flow the server's CAS says
	// whether it may; here the test plays that part.
	if err := alice.ApplyPendingCommit(); err != nil {
		t.Fatalf("apply pending commit: %v", err)
	}
	if err := bob.JoinVerified(welcome, trustAll{}); err != nil {
		t.Fatalf("join: %v", err)
	}
	return alice, bob, commit
}

func TestVersionNamesTheTwoFeaturesThisIntegrationNeeds(t *testing.T) {
	got, err := Version()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	for _, want := range []string{"mls-rs 0.56.0", "secret_tree_access", "export_key_generation"} {
		if !strings.Contains(got, want) {
			t.Fatalf("version %q does not mention %q", got, want)
		}
	}
}

// The commit has to leave as a PublicMessage and the application message as a
// PrivateMessage. Reading it off the bytes rather than off the setting is the
// point: an upstream default flipping under us would not change the setting we
// wrote, only what came out.
func TestControlMessagesGoOutPublicAndApplicationMessagesPrivate(t *testing.T) {
	alice, _, commit := twoMemberGroup(t)

	if got, err := WireFormOf(commit); err != nil || got != WireFormPublicMessage {
		t.Fatalf("commit wire form = %v, %v; want PublicMessage", got, err)
	}

	ciphertext, err := alice.Encrypt([]byte("the plaintext nobody else may read"), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, err := WireFormOf(ciphertext); err != nil || got != WireFormPrivateMessage {
		t.Fatalf("application wire form = %v, %v; want PrivateMessage", got, err)
	}
}

func TestApplicationMessageRoundTripsBetweenMembers(t *testing.T) {
	alice, bob, commit := twoMemberGroup(t)

	// Bob joined from the Welcome, so he is already at the new epoch and must
	// not be fed the commit that produced it.
	_ = commit

	plaintext := []byte("KT7 회의는 14시로 옮깁니다")
	ciphertext, err := alice.Encrypt(plaintext, []byte("declaration"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext carries the plaintext")
	}

	got, err := bob.Process(ciphertext)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !got.Application || !bytes.Equal(got.Plaintext, plaintext) {
		t.Fatalf("process = %+v; want the plaintext back", got)
	}
	if !bytes.Equal(got.AuthenticatedData, []byte("declaration")) {
		t.Fatalf("authenticated data came back as %q", got.AuthenticatedData)
	}
	// The generation has to arrive as a value, not as an absence. The
	// fail-closed rule refuses every message where it is missing, so a build
	// that lost export_key_generation would close the receive path entirely
	// and this is where that shows up.
	if got.KeyGeneration == nil {
		t.Fatal("the library reported no key generation; export_key_generation is not in this build")
	}
	if *got.KeyGeneration != 0 {
		t.Fatalf("first message decrypted at generation %d, want 0", *got.KeyGeneration)
	}
}

func TestSendPositionReportsWhatEncryptThenConsumes(t *testing.T) {
	alice, _, _ := twoMemberGroup(t)

	epoch, leaf, before, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}
	if _, err := alice.Encrypt([]byte("one"), nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	epochAfter, leafAfter, after, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}
	if after != before+1 {
		t.Fatalf("generation went %d -> %d; want one step", before, after)
	}
	if epochAfter != epoch || leafAfter != leaf {
		t.Fatalf("epoch/leaf moved on an encrypt: (%d,%d) -> (%d,%d)",
			epoch, leaf, epochAfter, leafAfter)
	}
}

// Burning is the recovery half of the send ordering: it has to move the
// ratchet exactly as far as an encrypt would, without producing anything.
func TestBurnGenerationAdvancesTheRatchetWithoutACiphertext(t *testing.T) {
	alice, bob, _ := twoMemberGroup(t)

	_, _, before, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}
	if err := alice.BurnGeneration(); err != nil {
		t.Fatalf("burn: %v", err)
	}
	_, _, after, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}
	if after != before+1 {
		t.Fatalf("burn moved the generation %d -> %d; want one step", before, after)
	}

	// The hole is ordinary. A receiver that never saw the burned generation
	// still opens the next one.
	plaintext := []byte("sent at the generation after the burned one")
	ciphertext, err := alice.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := bob.Process(ciphertext)
	if err != nil {
		t.Fatalf("process across the hole: %v", err)
	}
	if !bytes.Equal(got.Plaintext, plaintext) {
		t.Fatalf("plaintext across the hole = %q", got.Plaintext)
	}
	if got.KeyGeneration == nil || *got.KeyGeneration != after {
		t.Fatalf("decrypted at %v; want generation %d", got.KeyGeneration, after)
	}
}

// The burn only counts once it is on disk. mls-rs writes nothing by itself, so
// a burn followed by a crash before the flush is a burn that never happened.
func TestABurnIsOnlyDurableOnceTheStateIsWritten(t *testing.T) {
	store := newTestStore(t)
	alice, _, _ := twoMemberGroup(t)

	if _, err := Persist(store, testConv, chatstate.ServerWatermark{}, alice); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if err := alice.BurnGeneration(); err != nil {
		t.Fatalf("burn: %v", err)
	}
	if _, err := Persist(store, testConv, chatstate.ServerWatermark{}, alice); err != nil {
		t.Fatalf("persist after burn: %v", err)
	}

	restored := newSession(t, "alice@device-1")
	if found, err := Restore(store, testConv, chatstate.ServerWatermark{}, restored); err != nil || !found {
		t.Fatalf("restore = %v, %v", found, err)
	}
	_, _, generation, err := restored.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}
	if generation != 1 {
		t.Fatalf("the restored session is at generation %d; the burn did not survive", generation)
	}
}

func newTestStore(t *testing.T) *chatstate.Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	store, err := chatstate.Open(keychain.NewMemorySecretStore(), testOwner)
	if err != nil {
		t.Fatalf("open chat state store: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

// The whole point of the storage seam: what the library wrote into its storage
// provider survives a round trip through the sealed record and still opens the
// message it was holding keys for.
func TestGroupStateSurvivesTheChatStateRecord(t *testing.T) {
	store := newTestStore(t)
	alice, bob, _ := twoMemberGroup(t)

	if _, err := Persist(store, testConv, chatstate.ServerWatermark{}, bob); err != nil {
		t.Fatalf("persist: %v", err)
	}

	plaintext := []byte("sent while bob was away")
	ciphertext, err := alice.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// A second device process: a fresh session that knows nothing but what the
	// record holds.
	restored := newSession(t, "bob@device-1")
	found, err := Restore(store, testConv, chatstate.ServerWatermark{}, restored)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !found {
		t.Fatal("restore found no group state")
	}

	got, err := restored.Process(ciphertext)
	if err != nil {
		t.Fatalf("process after restore: %v", err)
	}
	if !bytes.Equal(got.Plaintext, plaintext) {
		t.Fatalf("restored session decrypted %q; want %q", got.Plaintext, plaintext)
	}
}

func TestRestoreReportsAConversationThatHasNoGroupYet(t *testing.T) {
	store := newTestStore(t)
	s := newSession(t, "alice@device-1")
	found, err := Restore(store, testConv, chatstate.ServerWatermark{}, s)
	if err != nil || found {
		t.Fatalf("restore on an empty conversation = %v, %v; want false, nil", found, err)
	}
}

// A malformed blob has to come back as an error rather than as a panic that the
// C ABI would turn into a dead Keeper.
func TestABadBlobIsRefusedRatherThanFatal(t *testing.T) {
	s := newSession(t, "alice@device-1")
	if err := s.Load([]byte("not a group state")); err == nil {
		t.Fatal("Load accepted a malformed blob")
	}
}

func TestCallsAfterCloseFailInsteadOfTouchingAFreedHandle(t *testing.T) {
	secret, public, err := generateSignatureKey()
	if err != nil {
		t.Fatalf("generate signature key: %v", err)
	}
	s, err := openSession([]byte("alice@device-1"), secret, public, nil)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	s.Close()
	s.Close()
	if err := s.CreateGroup([]byte("gid")); err == nil {
		t.Fatal("CreateGroup ran on a closed session")
	}
}

// ────────────────────────────────────────────────────────────────────────
// The transactions, with the real library behind them.
// ────────────────────────────────────────────────────────────────────────

const bobOwner = "33333333-3333-4333-8333-333333333333"

// twoMemberStores gives alice and bob a group each and a record each, under one
// state root and one mock keyring. Separate owners rather than separate roots
// because that is how the directory is actually partitioned.
func twoMemberStores(t *testing.T) (aliceStore, bobStore *chatstate.Store, alice, bob *Session) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	secrets := keychain.NewMemorySecretStore()

	var err error
	if aliceStore, err = chatstate.Open(secrets, testOwner); err != nil {
		t.Fatalf("open alice store: %v", err)
	}
	t.Cleanup(aliceStore.Close)
	if bobStore, err = chatstate.Open(secrets, bobOwner); err != nil {
		t.Fatalf("open bob store: %v", err)
	}
	t.Cleanup(bobStore.Close)

	alice, bob, _ = twoMemberGroup(t)
	if _, err := Persist(aliceStore, testConv, chatstate.ServerWatermark{}, alice); err != nil {
		t.Fatalf("persist alice: %v", err)
	}
	if _, err := Persist(bobStore, testConv, chatstate.ServerWatermark{}, bob); err != nil {
		t.Fatalf("persist bob: %v", err)
	}
	return aliceStore, bobStore, alice, bob
}

// End to end through both transactions: the declaration alice's send puts on
// the wire is the one bob's receive checks against what the library really
// decrypted with, and the delivery is confirmed together with its sealed copy.
func TestSendAndReceiveThroughTheStore(t *testing.T) {
	aliceStore, bobStore, alice, bob := twoMemberStores(t)
	plaintext := []byte("회의는 14시로 옮깁니다")

	sent, err := aliceStore.Send(testConv, chatstate.ServerWatermark{}, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-444444444444",
		Plaintext:       plaintext,
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !sent.Created || sent.Entry.Position.ContentType != chatstate.ContentTypeApplication {
		t.Fatalf("send = %+v", sent)
	}
	if bytes.Contains(sent.Entry.Ciphertext, plaintext) {
		t.Fatal("the stored ciphertext carries the plaintext")
	}
	if form, err := WireFormOf(sent.Entry.Ciphertext); err != nil || form != WireFormPrivateMessage {
		t.Fatalf("stored wire form = %v, %v", form, err)
	}

	got, err := bobStore.Receive(testConv, chatstate.ServerWatermark{}, chatstate.ReceiveRequest{
		Seq: 7, Message: sent.Entry.Ciphertext,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(got.Plaintext, plaintext) || !got.FirstDelivery || got.FromHistory {
		t.Fatalf("receive = %+v", got)
	}
	if got.Position != sent.Entry.Position {
		t.Fatalf("receive landed on %+v, send wrote %+v", got.Position, sent.Entry.Position)
	}

	// The re-read comes from the sealed copy. It has to: RFC 9420 §9.2 had the
	// message key deleted the moment the decrypt succeeded, so feeding the same
	// ciphertext back cannot work and is not what happens here.
	again, err := bobStore.Receive(testConv, chatstate.ServerWatermark{}, chatstate.ReceiveRequest{
		Seq: 7, Message: sent.Entry.Ciphertext,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !again.FromHistory || !bytes.Equal(again.Plaintext, plaintext) || again.Position != got.Position {
		t.Fatalf("re-read = %+v", again)
	}
	stored, err := bobStore.ReadHistory(testConv, chatstate.ServerWatermark{}, 7)
	if err != nil || !bytes.Equal(stored.Plaintext, plaintext) || stored.Position != got.Position {
		t.Fatalf("ReadHistory = %+v, %v", stored, err)
	}
}

// sealAborts stands in for a process that dies after the intent is durable and
// before the AEAD produces anything. The recovery that follows is the real one.
type sealAborts struct{ *Cipher }

func (sealAborts) Seal([]byte, []byte) ([]byte, error) {
	return nil, errors.New("the transport died before the AEAD")
}

func TestBurnForwardLeavesAHoleTheReceiverTakesInStride(t *testing.T) {
	aliceStore, bobStore, alice, bob := twoMemberStores(t)
	wm := chatstate.ServerWatermark{}

	if _, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-444444444444",
		Plaintext:       []byte("generation zero"),
	}, NewCipher(alice, trustAll{})); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Generation 1 gets an intent and never a ciphertext.
	if _, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "55555555-5555-4555-8555-555555555555",
		Plaintext:       []byte("never reaches the wire"),
	}, sealAborts{NewCipher(alice, trustAll{})}); err == nil {
		t.Fatal("the aborted send reported success")
	}

	// A fresh session, as a restart would have.
	restarted := newSession(t, "alice@device-1")
	recovered, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "66666666-6666-4666-8666-666666666666",
		Plaintext:       []byte("generation two"),
	}, NewCipher(restarted, trustAll{}))
	if err != nil {
		t.Fatalf("send after the aborted one: %v", err)
	}
	if len(recovered.Burned) != 1 || recovered.Burned[0].Generation != 1 {
		t.Fatalf("burned %+v; want generation 1 abandoned", recovered.Burned)
	}
	if recovered.Entry.Position.Generation != 2 {
		t.Fatalf("the recovered send landed on generation %d, want 2",
			recovered.Entry.Position.Generation)
	}

	got, err := bobStore.Receive(testConv, wm, chatstate.ReceiveRequest{
		Seq: 2, Message: recovered.Entry.Ciphertext,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("receive across the hole: %v", err)
	}
	if !bytes.Equal(got.Plaintext, []byte("generation two")) {
		t.Fatalf("receive across the hole = %q", got.Plaintext)
	}
}

// A declaration the sender did not write is a declaration the receiver refuses,
// and the refusal hands back nothing.
func TestReceiveRefusesAForgedDeclaration(t *testing.T) {
	aliceStore, bobStore, alice, bob := twoMemberStores(t)
	wm := chatstate.ServerWatermark{}

	sent, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-444444444444",
		Plaintext:       []byte("honestly declared"),
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	forged := &liesAboutTheDeclaration{Cipher: NewCipher(bob, trustAll{})}
	got, err := bobStore.Receive(testConv, wm, chatstate.ReceiveRequest{
		Seq: 1, Message: sent.Entry.Ciphertext,
	}, forged)
	if !errors.Is(err, chatstate.ErrDeclarationMismatch) {
		t.Fatalf("receive = %v, want ErrDeclarationMismatch", err)
	}
	if got.Plaintext != nil {
		t.Fatalf("a refused delivery returned %q", got.Plaintext)
	}
}

// liesAboutTheDeclaration rewrites what the sender declared, which is what a
// server that could edit authenticated_data without breaking the signature
// would achieve. It cannot, so this is the only way to reach the branch.
type liesAboutTheDeclaration struct{ *Cipher }

func (c *liesAboutTheDeclaration) Open(message []byte) (chatstate.Opened, error) {
	opened, err := c.Cipher.Open(message)
	if err != nil {
		return opened, err
	}
	opened.AuthenticatedData = []byte("dragpass.chat.mls|1|a|0|99")
	return opened, nil
}

// The same refusal when the library cannot report the generation at all, which
// is what a build without export_key_generation would do to every message.
func TestReceiveRefusesWhenTheGenerationIsUnreportable(t *testing.T) {
	aliceStore, bobStore, alice, bob := twoMemberStores(t)
	wm := chatstate.ServerWatermark{}

	sent, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-444444444444",
		Plaintext:       []byte("honestly declared"),
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	blind := &reportsNoGeneration{Cipher: NewCipher(bob, trustAll{})}
	got, err := bobStore.Receive(testConv, wm, chatstate.ReceiveRequest{
		Seq: 1, Message: sent.Entry.Ciphertext,
	}, blind)
	if !errors.Is(err, chatstate.ErrGenerationUnknown) {
		t.Fatalf("receive = %v, want ErrGenerationUnknown", err)
	}
	if got.Plaintext != nil {
		t.Fatalf("a refused delivery returned %q", got.Plaintext)
	}
}

type reportsNoGeneration struct{ *Cipher }

func (c *reportsNoGeneration) Open(message []byte) (chatstate.Opened, error) {
	opened, err := c.Cipher.Open(message)
	if err != nil {
		return opened, err
	}
	opened.KeyGeneration = nil
	return opened, nil
}

// ────────────────────────────────────────────────────────────────────────
// Pending commits against the real library (design §7.3, RFC 9420 §14).
// ────────────────────────────────────────────────────────────────────────

const (
	aliceCommitID = "77777777-7777-4777-8777-777777777777"
	bobCommitID   = "88888888-8888-4888-8888-888888888888"
)

// The MUST itself, with the library rather than a stand-in: building a Commit
// leaves the confirmed epoch and the send chain exactly where they were.
//
// The send chain part is the concrete shape of §7.3.4 under
// encrypt_control_messages=false. A Commit goes out as a PublicMessage, so it
// derives nothing from the handshake ratchet, and it does not touch the
// application ratchet either. There is no generation for a losing Commit to
// have consumed, so there is none to reclaim.
func TestBuildingACommitMovesNeitherTheEpochNorTheSendChain(t *testing.T) {
	alice, _, _ := twoMemberGroup(t)

	epochBefore, err := alice.Epoch()
	if err != nil {
		t.Fatalf("epoch: %v", err)
	}
	e0, leaf0, generation0, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position: %v", err)
	}

	commit, expected, err := alice.CommitUpdate()
	if err != nil {
		t.Fatalf("commit update: %v", err)
	}
	if expected != epochBefore {
		t.Fatalf("the commit was built against epoch %d, the group is on %d", expected, epochBefore)
	}
	if form, err := WireFormOf(commit); err != nil || form != WireFormPublicMessage {
		t.Fatalf("commit wire form = %v, %v; want PublicMessage", form, err)
	}

	if pending, err := alice.HasPendingCommit(); err != nil || !pending {
		t.Fatalf("has pending commit = %t, %v; want true", pending, err)
	}
	if got, err := alice.Epoch(); err != nil || got != epochBefore {
		t.Fatalf("building a commit moved the epoch from %d to %d (%v)", epochBefore, got, err)
	}
	e1, leaf1, generation1, err := alice.SendPosition()
	if err != nil {
		t.Fatalf("send position after build: %v", err)
	}
	if e0 != e1 || leaf0 != leaf1 || generation0 != generation1 {
		t.Fatalf("building a commit moved the send chain from (%d,%d,%d) to (%d,%d,%d)",
			e0, leaf0, generation0, e1, leaf1, generation1)
	}

	if err := alice.ApplyPendingCommit(); err != nil {
		t.Fatalf("apply pending commit: %v", err)
	}
	if got, err := alice.Epoch(); err != nil || got != epochBefore+1 {
		t.Fatalf("epoch after applying = %d, %v; want %d", got, err, epochBefore+1)
	}
}

// The "at most one pending" rule is the library's, not only the record's.
func TestTheLibraryRefusesASecondPendingCommit(t *testing.T) {
	alice, _, _ := twoMemberGroup(t)

	if _, _, err := alice.CommitUpdate(); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	_, _, err := alice.CommitUpdate()
	if err == nil {
		t.Fatal("a second commit was built while one was pending")
	}
	// mls-rs renders MlsError::ExistingPendingCommit as this string. Asserting
	// on it rather than only on "some error" is what would notice the refusal
	// moving to a different cause.
	if !strings.Contains(err.Error(), "commit already pending") {
		t.Fatalf("second commit failed with %v; want the existing-pending-commit error", err)
	}
}

// Losing a race, end to end through the store. Alice and bob both commit
// against the same epoch, the server picks bob's, and alice's confirmation has
// to drop her fork and apply bob's Commit to the epoch she never left. The
// proof that she did leave it correctly is that she can still open what bob
// sends at the epoch his Commit created.
func TestALostRaceAppliesTheWinnerFromTheEpochThatNeverMoved(t *testing.T) {
	aliceStore, bobStore, alice, bob := twoMemberStores(t)
	wm := chatstate.ServerWatermark{}

	aliceAttempt, err := aliceStore.BeginCommit(testConv, wm, chatstate.BeginCommitRequest{
		ClientCommitID: aliceCommitID,
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("alice begin commit: %v", err)
	}
	bobAttempt, err := bobStore.BeginCommit(testConv, wm, chatstate.BeginCommitRequest{
		ClientCommitID: bobCommitID,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("bob begin commit: %v", err)
	}
	if aliceAttempt.ExpectedEpoch != bobAttempt.ExpectedEpoch {
		t.Fatalf("the two commits were not built against one epoch: %d vs %d",
			aliceAttempt.ExpectedEpoch, bobAttempt.ExpectedEpoch)
	}

	// The server's compare-and-set picks bob.
	aliceOut, err := aliceStore.ConfirmCommit(testConv, wm, chatstate.CommitOutcome{
		ClientCommitID: aliceCommitID,
		Kind:           chatstate.CommitSuperseded,
		WinnerMessage:  bobAttempt.Commit,
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("alice confirm superseded: %v", err)
	}
	bobOut, err := bobStore.ConfirmCommit(testConv, wm, chatstate.CommitOutcome{
		ClientCommitID: bobCommitID,
		Kind:           chatstate.CommitAccepted,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("bob confirm accepted: %v", err)
	}
	if aliceOut.Epoch != bobOut.Epoch || aliceOut.Epoch != aliceAttempt.ExpectedEpoch+1 {
		t.Fatalf("the two diverged: alice %d, bob %d", aliceOut.Epoch, bobOut.Epoch)
	}
	if aliceOut.WelcomeReleasable || aliceOut.Removed {
		t.Fatalf("the losing side released something: %+v", aliceOut)
	}
	if pending, err := alice.HasPendingCommit(); err != nil || pending {
		t.Fatalf("alice's fork survived her loss: %t, %v", pending, err)
	}

	plaintext := []byte("보낸 쪽이 이겼습니다")
	sent, err := bobStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "44444444-4444-4444-8444-444444444444",
		Plaintext:       plaintext,
	}, NewCipher(bob, trustAll{}))
	if err != nil {
		t.Fatalf("bob send after winning: %v", err)
	}
	got, err := aliceStore.Receive(testConv, wm, chatstate.ReceiveRequest{
		Seq: 1, Message: sent.Entry.Ciphertext,
	}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("alice receive after losing: %v", err)
	}
	if !bytes.Equal(got.Plaintext, plaintext) {
		t.Fatalf("alice decrypted %q; want %q", got.Plaintext, plaintext)
	}
}

// The persistence form in one assertion: the fork rides inside the group state
// blob, so a session that knows nothing but what the record holds is still
// waiting on the same Commit and can still accept it.
func TestAPendingCommitRidesTheGroupStateBlob(t *testing.T) {
	store := newTestStore(t)
	alice, _, _ := twoMemberGroup(t)
	charlie := newSession(t, "charlie@device-1")
	keyPackage, err := charlie.KeyPackage()
	if err != nil {
		t.Fatalf("key package: %v", err)
	}
	if _, err := Persist(store, testConv, chatstate.ServerWatermark{}, alice); err != nil {
		t.Fatalf("persist: %v", err)
	}

	attempt, err := store.BeginCommit(testConv, chatstate.ServerWatermark{},
		chatstate.BeginCommitRequest{
			ClientCommitID: aliceCommitID,
			Plan:           chatstate.CommitPlan{AddKeyPackages: [][]byte{keyPackage}},
		}, NewCipher(alice, trustAll{}))
	if err != nil {
		t.Fatalf("begin commit: %v", err)
	}
	if len(attempt.Welcome) == 0 || attempt.WelcomeReleasable {
		t.Fatalf("begin = %+v; a welcome must exist and must not be releasable yet", attempt)
	}

	restored := newSession(t, "alice@device-1")
	found, err := Restore(store, testConv, chatstate.ServerWatermark{}, restored)
	if err != nil || !found {
		t.Fatalf("restore = %t, %v", found, err)
	}
	if pending, err := restored.HasPendingCommit(); err != nil || !pending {
		t.Fatalf("the fork did not survive the record: %t, %v", pending, err)
	}
	if got, err := restored.Epoch(); err != nil || got != attempt.ExpectedEpoch {
		t.Fatalf("the restored epoch is %d, %v; want the confirmed %d",
			got, err, attempt.ExpectedEpoch)
	}

	out, err := store.ConfirmCommit(testConv, chatstate.ServerWatermark{},
		chatstate.CommitOutcome{ClientCommitID: aliceCommitID, Kind: chatstate.CommitAccepted},
		NewCipher(restored, trustAll{}))
	if err != nil {
		t.Fatalf("confirm after restore: %v", err)
	}
	if out.Epoch != attempt.ExpectedEpoch+1 || !out.WelcomeReleasable {
		t.Fatalf("confirm after restore = %+v", out)
	}
	if err := charlie.JoinVerified(out.Welcome, trustAll{}); err != nil {
		t.Fatalf("the released welcome did not admit the new member: %v", err)
	}
}

// §16's unmeasured item. A pending Commit carries the next epoch's state,
// epoch secrets and key schedule, so while one is outstanding the record holds
// two epochs' worth of secrets. The numbers go in the test log rather than in
// an assertion on an exact size, which would only track this group shape; what
// is asserted is the direction, which is the claim being checked.
func TestAPendingCommitEnlargesTheStoredBlob(t *testing.T) {
	alice, _, _ := twoMemberGroup(t)

	confirmed, err := alice.Flush()
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, _, err := alice.CommitUpdate(); err != nil {
		t.Fatalf("commit update: %v", err)
	}
	withPending, err := alice.Flush()
	if err != nil {
		t.Fatalf("flush with pending: %v", err)
	}
	t.Logf("two-member group state: confirmed %d bytes, with a pending commit %d bytes (+%d)",
		len(confirmed), len(withPending), len(withPending)-len(confirmed))

	if len(withPending) <= len(confirmed) {
		t.Fatalf("a pending commit did not enlarge the blob: %d vs %d",
			len(withPending), len(confirmed))
	}
	if err := alice.ApplyPendingCommit(); err != nil {
		t.Fatalf("apply pending commit: %v", err)
	}
	applied, err := alice.Flush()
	if err != nil {
		t.Fatalf("flush after applying: %v", err)
	}
	t.Logf("after applying: %d bytes", len(applied))
	if len(applied) >= len(withPending) {
		t.Fatalf("settling the commit did not shrink the blob: %d vs %d",
			len(applied), len(withPending))
	}
}

// The device key is minted in Go (crypto/ed25519) by mls_leaf_declare, not by
// the library, so this is what shows mls-rs accepts that layout as a signer and
// that the leaf it builds carries the declared key and identity.
func TestNewDeviceSession_SignsWithTheDeclaredKey(t *testing.T) {
	store := keychain.NewMemorySecretStore()
	if _, _, err := NewDeviceSession(store); !errors.Is(err, ErrNoLeafKey) {
		t.Fatalf("NewDeviceSession with no key = %v; want ErrNoLeafKey", err)
	}

	public, secret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const device = "44444444-4444-4444-8444-444444444444"
	if err := keychain.SaveMLSLeafKey(store, keychain.MLSLeafKey{
		AccountID: testOwner, DeviceID: device, SecretKey: secret, PublicKey: public,
		Declaration: []byte("the active declaration"),
	}); err != nil {
		t.Fatal(err)
	}

	alice, used, err := NewDeviceSession(store)
	if err != nil {
		t.Fatalf("NewDeviceSession: %v", err)
	}
	t.Cleanup(alice.Close)
	if used.AccountID != testOwner || used.DeviceID != device || !bytes.Equal(used.PublicKey, public) ||
		!bytes.Equal(used.Declaration, []byte("the active declaration")) {
		t.Fatal("NewDeviceSession did not report the leaf it was built from")
	}
	kp, err := alice.KeyPackage()
	if err != nil {
		t.Fatalf("key package: %v", err)
	}
	leaf, err := keyPackageLeaf(kp)
	if err != nil || !bytes.Equal(leaf.Declaration, []byte("the active declaration")) {
		t.Fatalf("the key package does not carry the stored declaration unchanged: %v", err)
	}
	if !bytes.Equal(leaf.SignatureKey, used.PublicKey) {
		t.Fatal("the key package's leaf signs with a key other than the one reported")
	}
	if !bytes.Contains(kp, public) {
		t.Fatal("key package does not carry the declared leaf signature key")
	}
	if !bytes.Contains(kp, CredentialIdentity(testOwner, device)) {
		t.Fatal("key package does not carry the device credential identity")
	}

	// bob joining and opening alice's message proves the key signs and
	// verifies, not only that it serializes.
	if err := alice.CreateGroup([]byte("device-session-group")); err != nil {
		t.Fatalf("create group: %v", err)
	}
	bob := newSession(t, "bob@device-1")
	bobKP, err := bob.KeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	_, welcome, _, err := alice.CommitAddMemberVerified(bobKP, trustAll{})
	if err != nil {
		t.Fatalf("commit add member: %v", err)
	}
	if err := alice.ApplyPendingCommit(); err != nil {
		t.Fatal(err)
	}
	if err := bob.JoinVerified(welcome, trustAll{}); err != nil {
		t.Fatalf("join a group created by a device session: %v", err)
	}
	ciphertext, err := alice.Encrypt([]byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	processed, err := bob.Process(ciphertext)
	if err != nil || string(processed.Plaintext) != "hello" {
		t.Fatalf("bob could not open alice's message: %v", err)
	}
}
