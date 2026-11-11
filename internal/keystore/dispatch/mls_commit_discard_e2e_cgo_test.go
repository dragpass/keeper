//go:build mls && cgo

// mls_commit_discard_refused end to end through the dispatcher with the real
// MLS library: a Commit the server definitively refused is dropped, the
// confirmed state keeps working, the same intent rebuilds on it, and every
// discard that names another Commit, an accepted one, or one from an earlier
// sign-in is refused without writing.

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// signIn commits a chat login for this Keeper's account and returns its
// generation, as the App's sign-in does.
func (k *keeper) signIn(intent string) string {
	k.t.Helper()
	state, err := keychain.ReadChatLogin(k.store)
	if err != nil {
		k.t.Fatal(err)
	}
	if err := keychain.PrepareChatLogin(k.store, intent, state.Generation, state.PreparationSequence); err != nil {
		k.t.Fatalf("prepare chat login: %v", err)
	}
	committed, _, err := keychain.CommitChatLogin(k.store, intent, k.id, "alias")
	if err != nil {
		k.t.Fatalf("commit chat login: %v", err)
	}
	return committed.Generation
}

func (k *keeper) discardRefusedRequest(id string, epoch uint64, code string) proto.MLSCommitDiscardRefusedRequest {
	return proto.MLSCommitDiscardRefusedRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, ExpectedEpoch: epoch, RefusalCode: code,
	}
}

func TestMLSChatE2E_ARefusedCommitIsDiscardedAndTheIntentRebuilt(t *testing.T) {
	c := newDM(t)
	c.alice.signIn("intent-1")

	refused := c.alice.buildUpdate(1)
	c.alice.assertStatus(c.alice.status(), 1, refused.ClientCommitID)

	// Refusals first; none writes.
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(c.alice.nextCommitID(), 1, "CHAT_MLS_REMOVAL_PENDING"),
		string(errs.ErrCodeChatStateConflict))
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(refused.ClientCommitID, 2, "CHAT_MLS_REMOVAL_PENDING"),
		string(errs.ErrCodeChatStateConflict))
	for _, code := range []string{"CHAT_MLS_EPOCH_STALE", "CHAT_INTERNAL", "", "network"} {
		c.alice.refused(proto.MLSCommitDiscardRefused,
			c.alice.discardRefusedRequest(refused.ClientCommitID, 1, code),
			string(errs.ErrCodeChatStateInvalidInput))
	}
	c.alice.assertStatus(c.alice.status(), 1, refused.ClientCommitID)

	got := c.alice.must(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(refused.ClientCommitID, 1, "CHAT_MLS_REMOVAL_PENDING")).
		Data.(proto.MLSCommitDiscardRefusedResponseData)
	if !got.Discarded {
		t.Fatalf("discard = %+v", got)
	}
	c.alice.assertStatus(c.alice.status(), 1, "")

	// Not idempotent: nothing pending now, so a repeat is refused.
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(refused.ClientCommitID, 1, "CHAT_MLS_REMOVAL_PENDING"),
		string(errs.ErrCodeChatStateConflict))

	// The confirmed epoch still carries messages both ways.
	assertShown(t, c.bob.decrypt(c.send(c.alice, 1, 1, "still epoch 1")), 0, "still epoch 1", c.alice, false)

	// The same intent rebuilt under a new id lands, and Bob applies it.
	rebuilt := c.alice.buildUpdate(1)
	if rebuilt.ClientCommitID == refused.ClientCommitID || !rebuilt.Created {
		t.Fatalf("rebuild = %+v", rebuilt)
	}
	c.alice.confirm(rebuilt.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, rebuilt.CommitB64)
	c.alice.assertStatus(c.alice.status(), 2, "")
	c.bob.assertStatus(c.bob.status(), 2, "")

	// An accepted Commit is never discarded.
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(rebuilt.ClientCommitID, 1, "CHAT_ACCESS_DENIED"),
		string(errs.ErrCodeChatStateConflict))
	c.alice.assertStatus(c.alice.status(), 2, "")
}

// A discard decided before a sign-out and sign-in reaches the Keeper after
// the new sign-in: the Commit was built under the earlier one.
func TestMLSChatE2E_AStaleRefusedCommitDiscardAfterReLoginIsRefused(t *testing.T) {
	c := newDM(t)
	first := c.alice.signIn("intent-1")
	refused := c.alice.buildUpdate(1)

	second := c.alice.signIn("intent-2")
	if second == first {
		t.Fatal("the second sign-in kept the generation")
	}
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(refused.ClientCommitID, 1, "CHAT_ROOM_OWNER_LEAVING"),
		string(errs.ErrCodeChatStateConflict))
	c.alice.assertStatus(c.alice.status(), 1, refused.ClientCommitID)
}

// A Commit built while no chat sign-in is confirmed is never discarded this
// way; it stays for the log to settle.
func TestMLSChatE2E_ACommitBuiltWithoutASignInIsNotDiscarded(t *testing.T) {
	c := newDM(t)
	refused := c.alice.buildUpdate(1)
	c.alice.signIn("intent-1")
	c.alice.refused(proto.MLSCommitDiscardRefused,
		c.alice.discardRefusedRequest(refused.ClientCommitID, 1, "CHAT_MLS_REMOVAL_PENDING"),
		string(errs.ErrCodeChatStateConflict))
	c.alice.assertStatus(c.alice.status(), 1, refused.ClientCommitID)
}
