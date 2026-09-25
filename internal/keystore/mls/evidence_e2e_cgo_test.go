//go:build mls && cgo

// One evidence document for both rules (proto.MLSCommitEvidence): a Commit
// that replaces Bob's leaf on his old device's handover and removes Dave on
// his signed leave carries both in the same authenticated data, and Carol's
// Keeper applies it only when each rule finds what it needs there.

package mls_test

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const accountD = "d4444444-4444-4444-8444-444444444444"

type evidenceGroup struct {
	succession
	dave *account
}

// newEvidenceGroup is Alice, Bob, Dave and Carol, Carol joining last so that
// she holds every leaf, and Bob's new machine declared and ready to take his
// seat.
func newEvidenceGroup(t *testing.T) evidenceGroup {
	t.Helper()
	g := newGroup(t)
	bob := newAccount(t, accountB)
	g.memberOf(t, bob, device1)
	dave := newAccount(t, accountD)
	g.memberOf(t, dave, device1)
	carol := newAccount(t, accountC)
	carolS, carolStore := g.memberOf(t, carol, device1)
	bob2 := sameAccount(t, bob)
	decl := bob2.declare(t, device2, proto.MLSLeafReasonRotate, time.Now().Unix()+60)
	return evidenceGroup{
		succession: succession{
			g: g, bob: bob, bob2: bob2, decl: decl, bob2KP: keyPackage(t, bob2.session(t)),
			carol: carol, carolS: carolS, carolStore: carolStore,
		},
		dave: dave,
	}
}

func (e evidenceGroup) daveLeaves(t *testing.T) proto.MLSLeaveStatement {
	t.Helper()
	st := proto.MLSLeaveStatement{ConversationID: conv, AccountID: accountD, RequestedAt: time.Now().Unix()}
	sig, err := crypto.SignData(e.dave.priv, proto.MLSLeaveCanonical(st))
	if err != nil {
		t.Fatal(err)
	}
	st.Signature = base64.StdEncoding.EncodeToString(sig)
	return st
}

// craftBoth is Alice's client building, straight on her session, one Commit
// that removes Bob's old leaf and Dave's leaf and adds Bob's new one.
func (e evidenceGroup) craftBoth(t *testing.T, ev proto.MLSCommitEvidence) []byte {
	t.Helper()
	roster, err := e.g.aliceS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	var out []mls.Leaf
	for _, l := range roster {
		if a, _, _ := mls.ParseCredentialIdentity(l.Identity); a == accountB || a == accountD {
			out = append(out, l)
		}
	}
	if len(out) != 2 {
		t.Fatalf("leaves to remove = %d; want bob's and dave's", len(out))
	}
	ad, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.g.aliceS.ApproveRemovalsForTest(out); err != nil {
		t.Fatal(err)
	}
	if err := e.g.aliceS.SetNextCommitAADForTest(ad); err != nil {
		t.Fatal(err)
	}
	commit, _, _, err := e.g.aliceS.CommitReplaceMembersVerified(
		[]uint32{out[0].Index, out[1].Index}, [][]byte{e.bob2KP}, trustAll{})
	if err != nil {
		t.Fatalf("alice could not build the commit: %v", err)
	}
	return commit
}

// carolReceivesWithEvidence applies the Commit with the statement verifier
// every MLS action sets on its cipher.
func (e evidenceGroup) carolReceivesWithEvidence(commit []byte) (chatstate.ReceiveResult, error) {
	cipher := mls.NewCipher(e.carolS, e.carol.verifier())
	cipher.SetEvidence(handlers.NewStatementEvidence(e.carol.deps,
		proto.ChatStatePermit{AccountID: accountC, ConversationID: conv}))
	return e.carolStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: 10, Message: commit}, cipher)
}

func TestEvidence_ACommitCarryingAHandoverAndALeaveVerifiesUnderBothRules(t *testing.T) {
	e := newEvidenceGroup(t)
	handover := e.signedHandover(t, e.decl).Wire()
	commit := e.craftBoth(t, proto.MLSCommitEvidence{
		Leaves:    []proto.MLSLeaveStatement{e.daveLeaves(t)},
		Handovers: []proto.MLSLeafHandover{handover},
	})
	if _, err := e.carolReceivesWithEvidence(commit); err != nil {
		t.Fatalf("receive = %v", err)
	}
	roster, err := e.carolS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	bobDevices := map[string]bool{}
	for _, l := range roster {
		a, d, _ := mls.ParseCredentialIdentity(l.Identity)
		if a == accountD {
			t.Fatal("dave is still in the group")
		}
		if a == accountB {
			bobDevices[d] = true
		}
	}
	if !bobDevices[device2] || bobDevices[device1] || len(bobDevices) != 1 {
		t.Fatalf("bob's leaves = %v; want only the new device", bobDevices)
	}
}

// The same Commit missing either half is refused: each rule reads its own
// part of the document and finds nothing standing in for the other.
func TestEvidence_EachRuleStillNeedsItsOwnPart(t *testing.T) {
	for name, ev := range map[string]func(*testing.T, evidenceGroup) proto.MLSCommitEvidence{
		"leave without the handover": func(t *testing.T, e evidenceGroup) proto.MLSCommitEvidence {
			return proto.MLSCommitEvidence{Leaves: []proto.MLSLeaveStatement{e.daveLeaves(t)}}
		},
		"handover without the leave": func(t *testing.T, e evidenceGroup) proto.MLSCommitEvidence {
			return proto.MLSCommitEvidence{Handovers: []proto.MLSLeafHandover{e.signedHandover(t, e.decl).Wire()}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEvidenceGroup(t)
			_, err := e.carolReceivesWithEvidence(e.craftBoth(t, ev(t, e)))
			var blocked *chatstate.SyncBlockedError
			if !errors.As(err, &blocked) || blocked.Block.Cause != chatstate.SyncBlockUnauthorizedCommit {
				t.Fatalf("receive = %v; want an unauthorized_commit block", err)
			}
		})
	}
}
