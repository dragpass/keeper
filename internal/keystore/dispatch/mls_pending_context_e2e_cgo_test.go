//go:build mls && cgo

package dispatch

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The app's note of a pending Commit is gone (browser data cleared) and the
// log has no row for it. The Keeper still hands back what the app wrote with
// the Commit, and a rebuild under the same id is the same Commit and Welcome,
// so the app can post it again instead of staying commit_pending for good.
func TestMLSChatE2E_APendingCommitComesBackWithItsAppContextForARepost(t *testing.T) {
	c := newDM(t)
	carol := newKeeper(t, "c3333333-3333-4333-8333-333333333333")
	context := base64.StdEncoding.EncodeToString([]byte(`{"v":1,"flow":"chat","kind":"add"}`))
	build := proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1,
		Add: []proto.MLSMemberKeyPackage{carol.keyPackage()}, AppContextB64: context,
	}
	first := commitOf(c.alice.must(proto.MLSCommitBuild, build))

	status := c.alice.status()
	if !status.CommitPending || status.PendingClientCommitID != build.ClientCommitID ||
		status.PendingAppContextB64 != context {
		t.Fatalf("status with a pending Commit = %+v", status)
	}
	again := commitOf(c.alice.must(proto.MLSCommitBuild, build))
	if again.Created || again.CommitB64 != first.CommitB64 || again.WelcomeB64 != first.WelcomeB64 {
		t.Fatal("the rebuild under the same id is not the first Commit")
	}

	c.alice.confirm(build.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := c.alice.status(); got.CommitPending || got.PendingAppContextB64 != "" || got.Epoch != 2 {
		t.Fatalf("status after the verdict = %+v", got)
	}
	carol.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: carol.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: first.WelcomeB64,
	})
	c.bob.process(c.nextSeq(), 2, first.CommitB64)
}

// A room Commit's name comes back from the status when the app lost the
// build's answer, and it opens once the Commit is the epoch's.
func TestMLSChatE2E_APendingCommitReportsTheNameItsFirstBuildSealed(t *testing.T) {
	c := newDM(t)
	build := proto.MLSCommitBuildRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), ExpectedEpoch: 1, UpdateSelf: true,
		RoomNamePlaintextB64: base64.StdEncoding.EncodeToString([]byte("새 이름")),
	}
	first := commitOf(c.alice.must(proto.MLSCommitBuild, build))
	status := c.alice.status()
	if first.NameCiphertextB64 == "" || status.PendingNameCiphertextB64 != first.NameCiphertextB64 ||
		status.PendingNameIVb64 != first.NameIVb64 || status.PendingNameEpoch != 2 {
		t.Fatalf("status = %+v; first build = %+v", status, first)
	}
	build.RoomNamePlaintextB64 = ""
	if retry := commitOf(c.alice.must(proto.MLSCommitBuild, build)); retry.NameCiphertextB64 != "" {
		t.Fatal("a retry that asked for no name answered with one")
	}
	c.alice.confirm(build.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	opened := c.alice.must(proto.MLSRoomNameOpen, proto.MLSRoomNameOpenRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		Epoch: 2, NameIVb64: status.PendingNameIVb64, NameCiphertextB64: status.PendingNameCiphertextB64,
	}).Data.(proto.MLSDisplayResponseData)
	if plaintextOf(t, opened.PlaintextB64[0]) != "새 이름" {
		t.Fatal("the stored name does not open at the Commit's epoch")
	}
}
