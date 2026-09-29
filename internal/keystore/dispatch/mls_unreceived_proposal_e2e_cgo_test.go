//go:build mls && cgo

package dispatch

import (
	"bytes"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/mls/mlsadversary"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func TestMLSChatE2E_ACommitReferencingAnUnreceivedProposalIsRefusedWithoutStateChange(t *testing.T) {
	r := newAdvRoom(t, true)
	dave := newKeeper(t, "d4444444-4444-4444-8444-444444444444")
	proposal := r.adv.ProposeAdd(unb64(t, dave.keyPackage().KeyPackageB64))
	commit, _ := r.adv.Build(mlsadversary.Commit{Apply: true})
	if len(proposal) == 0 || len(commit) == 0 {
		t.Fatal("the adversary did not build a proposal-backed Commit")
	}

	if got := r.alice.status(); got.Epoch != 1 {
		t.Fatalf("alice advanced before receiving the Commit: %+v", got)
	}
	before := stateOf(t, r.alice)
	request := r.alice.processRequest(r.nextSeq(), 2, advB64(commit))
	request.CommitAttestation = attested(e2eAlice, e2eCarol, advMallory, dave.id)
	response := r.alice.call(proto.MLSProcess, request)
	if response.Success || string(response.ErrorCode) != proto.ChatMLSErrorCodeFailed {
		t.Fatalf("a Commit referencing a proposal alice never received = %+v", response)
	}
	if got := r.alice.status(); got.Epoch != 1 || got.SyncBlocked != nil || got.NeedsRekey {
		t.Fatalf("the refusal changed alice's MLS status: %+v", got)
	}
	after := stateOf(t, r.alice)
	if len(before.files) != len(after.files) || len(before.secrets) != len(after.secrets) || len(before.anchors) != len(after.anchors) {
		t.Fatal("the refused Commit changed persisted Keeper state")
	}
	for path, value := range before.files {
		if !bytes.Equal(value, after.files[path]) {
			t.Fatalf("the refused Commit changed state file %s", path)
		}
	}
	for key, value := range before.secrets {
		if after.secrets[key] != value {
			t.Fatalf("the refused Commit changed keyring entry %s", key)
		}
	}
	for key, value := range before.anchors {
		if after.anchors[key] != value {
			t.Fatalf("the refused Commit changed anchor %s", key)
		}
	}

	valid := r.alice.buildUpdate(1)
	r.alice.confirm(valid.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.carol.processAttested(r.nextSeq(), 2, valid.CommitB64, e2eAlice, e2eCarol, advMallory); got.Epoch != 2 {
		t.Fatalf("carol could not apply a valid Commit after alice's refusal: %+v", got)
	}
}
