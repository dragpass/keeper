//go:build mls && cgo

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

func (k *keeper) readOutbox(id string) proto.ChatStateReadOutboxResponseData {
	k.t.Helper()
	return k.must(proto.ChatStateReadOutbox, proto.ChatStateReadOutboxRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientMessageID: id,
	}).Data.(proto.ChatStateReadOutboxResponseData)
}

// An app that lost mls_encrypt's answer (its process died before the POST)
// and deliberately kept no plaintext can still post the message: the outbox
// gives back the same bytes and the whole position the POST declares.
func TestMLSChatE2E_AnOutboxEntryReadsBackWithItsMLSPositionAndNoPlaintext(t *testing.T) {
	c := newDM(t)
	c.alice.encrypt(messageID(1), 1, "first")
	sent := c.alice.encrypt(messageID(2), 1, "second")

	got := c.alice.readOutbox(messageID(2))
	if got.CiphertextB64 != sent.CiphertextB64 || got.Epoch != sent.Epoch ||
		got.ChainIndex != sent.Generation || got.LeafIndex != sent.LeafIndex ||
		got.ContentType != sent.ContentType {
		t.Fatalf("read outbox = %+v; encrypt answered %+v", got, sent)
	}
	// What was read back is the message that was encrypted, not a new one.
	assertShown(t, c.bob.decrypt(proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: got.CiphertextB64}),
		0, "second", c.alice, false)

	c.alice.refused(proto.ChatStateReadOutbox, proto.ChatStateReadOutboxRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv, ClientMessageID: messageID(3),
	}, proto.ChatStateErrorCodeNotFound)
}
