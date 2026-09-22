//go:build mls && cgo

package mls

import (
	"bytes"
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

func newSession(t *testing.T, identity string) *Session {
	t.Helper()
	secret, public, err := GenerateSignatureKey()
	if err != nil {
		t.Fatalf("generate signature key: %v", err)
	}
	s, err := NewSession([]byte(identity), secret, public)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// twoMemberGroup returns alice (the creator), bob (joined via Welcome) and the
// commit alice produced, so tests can assert on the wire form of real output.
func twoMemberGroup(t *testing.T) (alice, bob *Session, commit []byte) {
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
	commit, welcome, err := alice.AddMember(kp)
	if err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := bob.Join(welcome); err != nil {
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
	secret, public, err := GenerateSignatureKey()
	if err != nil {
		t.Fatalf("generate signature key: %v", err)
	}
	s, err := NewSession([]byte("alice@device-1"), secret, public)
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
	}, NewCipher(alice))
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
	}, NewCipher(bob))
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
	}, NewCipher(bob))
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if !again.FromHistory || !bytes.Equal(again.Plaintext, plaintext) {
		t.Fatalf("re-read = %+v", again)
	}
	stored, err := bobStore.ReadHistory(testConv, chatstate.ServerWatermark{}, 7)
	if err != nil || !bytes.Equal(stored, plaintext) {
		t.Fatalf("ReadHistory = %q, %v", stored, err)
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
	}, NewCipher(alice)); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Generation 1 gets an intent and never a ciphertext.
	if _, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "55555555-5555-4555-8555-555555555555",
		Plaintext:       []byte("never reaches the wire"),
	}, sealAborts{NewCipher(alice)}); err == nil {
		t.Fatal("the aborted send reported success")
	}

	// A fresh session, as a restart would have.
	restarted := newSession(t, "alice@device-1")
	recovered, err := aliceStore.Send(testConv, wm, chatstate.SendRequest{
		ClientMessageID: "66666666-6666-4666-8666-666666666666",
		Plaintext:       []byte("generation two"),
	}, NewCipher(restarted))
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
	}, NewCipher(bob))
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
	}, NewCipher(alice))
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	forged := &liesAboutTheDeclaration{Cipher: NewCipher(bob)}
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
	}, NewCipher(alice))
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	blind := &reportsNoGeneration{Cipher: NewCipher(bob)}
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
