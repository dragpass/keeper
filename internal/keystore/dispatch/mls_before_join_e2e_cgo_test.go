//go:build mls && cgo

package dispatch

import (
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// Carol is added at epoch 2, after Alice and Bob have already talked at
// epoch 1. An app that lost its record of where Carol joined hands her the
// whole page from seq 1. The message from before she joined belongs to an
// epoch she never had; it comes back as before_join, with no plaintext and no
// sender, and the rest of the page is shown.
func TestMLSChatE2E_AMessageFromBeforeTheJoinIsMarkedAndDoesNotRefuseThePage(t *testing.T) {
	c := newDM(t)
	early := c.send(c.alice, 1, 1, "before carol")

	carol := newKeeper(t, e2eCarol)
	add := commitOf(c.alice.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()},
	}))
	c.alice.confirm(add.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.bob.process(c.nextSeq(), 2, add.CommitB64)
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: add.WelcomeB64,
	})
	late := c.send(c.alice, 2, 2, "after carol")

	resp := carol.call(proto.MLSDecryptBatchForAppDisplay, carol.decryptRequest(early, late))
	if !resp.Success {
		t.Fatalf("a page holding a message from before the join was refused: %s (%s)", resp.Error, resp.ErrorCode)
	}
	got := resp.Data.(proto.MLSDisplayResponseData)
	if item := got.Items[0]; item.State != proto.MLSDisplayItemStateBeforeJoin || got.PlaintextB64[0] != "" ||
		item.Seq != early.Seq || item.SenderAccountID != "" || item.Epoch != 0 {
		t.Fatalf("pre-join item = %+v %q", item, got.PlaintextB64[0])
	}
	assertShown(t, got, 1, "after carol", c.alice, false)

	// Nothing was written for it: it is before_join again, never
	// history_unavailable, and the page still reads.
	again := carol.decrypt(early, late)
	if again.Items[0].State != proto.MLSDisplayItemStateBeforeJoin {
		t.Fatalf("second read of the pre-join item = %+v", again.Items[0])
	}
	assertShown(t, again, 1, "after carol", c.alice, true)

	// A member who was there opens it as before.
	assertShown(t, c.bob.decrypt(early), 0, "before carol", c.alice, false)
}
