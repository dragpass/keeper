//go:build mls && cgo

package mls

import (
	"bytes"
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

	ciphertext, err := alice.Encrypt([]byte("the plaintext nobody else may read"))
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
	ciphertext, err := alice.Encrypt(plaintext)
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
}

func TestPeekReportsTheGenerationEncryptThenConsumes(t *testing.T) {
	alice, _, _ := twoMemberGroup(t)

	before, err := alice.PeekGeneration()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if _, err := alice.Encrypt([]byte("one")); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	after, err := alice.PeekGeneration()
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if after != before+1 {
		t.Fatalf("peek went %d -> %d; want one step", before, after)
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
	ciphertext, err := alice.Encrypt(plaintext)
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
