//go:build mls && cgo

// The succession rule at the receiver (chatstate/succession.go, design Q1,
// Q2), through real MLS: a member whose client skips its Keeper's checks
// builds a replace of Bob's leaf with Bob2's, and Carol's Keeper decides from
// the Commit alone, with the handovers its authenticated data carries.

package mls_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// sameAccount is a new machine of a's account: the account key pair and
// nothing else, as a password login would give it.
func sameAccount(t testing.TB, a *account) *account {
	t.Helper()
	b := newAccount(t, a.id)
	priv, err := keychain.GetPrivateKey(a.store)
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(b.store, priv); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(b.store, a.pem); err != nil {
		t.Fatal(err)
	}
	b.pem, b.priv = a.pem, a.priv
	return b
}

type succession struct {
	g          groupOf
	bob, bob2  *account
	decl       proto.MLSLeafDeclaration
	bob2KP     []byte
	carol      *account
	carolS     *mls.Session
	carolStore *chatstate.Store
}

func newSuccession(t *testing.T) succession {
	t.Helper()
	g := newGroup(t)
	bob := newAccount(t, accountB)
	g.memberOf(t, bob, device1)
	carol := newAccount(t, accountC)
	carolS, carolStore := g.memberOf(t, carol, device1)
	bob2 := sameAccount(t, bob)
	decl := bob2.declare(t, device2, proto.MLSLeafReasonRotate, time.Now().Unix()+60)
	return succession{
		g: g, bob: bob, bob2: bob2, decl: decl, bob2KP: keyPackage(t, bob2.session(t)),
		carol: carol, carolS: carolS, carolStore: carolStore,
	}
}

// signedHandover is Bob's old device approving decl through its Keeper.
func (s succession) signedHandover(t *testing.T, decl proto.MLSLeafDeclaration) chatstate.LeafHandover {
	t.Helper()
	resp := handlers.HandleMLSLeafHandoverSign(s.bob.deps, proto.MLSLeafHandoverSignRequest{
		AccountID: s.bob.id, NewDeclaration: decl, ExpiresAt: time.Now().Unix() + 600,
	})
	if !resp.Success {
		t.Fatalf("handover sign: %s", resp.Error)
	}
	w := resp.Data.(proto.MLSLeafHandoverSignResponseData).Handover
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return chatstate.LeafHandover{
		AccountID: w.AccountID, OldDeviceID: w.OldDeviceID, OldFingerprint: w.OldSignatureKeyFP,
		NewDeviceID: w.NewDeviceID, NewFingerprint: w.NewSignatureKeyFP,
		IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt, Signature: sig,
	}
}

// craft is Alice's client building the replace straight on her session with
// the authenticated data it chooses.
func (s succession) craft(t *testing.T, ad []byte) []byte {
	t.Helper()
	roster, err := s.g.aliceS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	var old []mls.Leaf
	for _, l := range roster {
		if a, _, _ := mls.ParseCredentialIdentity(l.Identity); a == accountB {
			old = append(old, l)
		}
	}
	if err := s.g.aliceS.ApproveRemovalsForTest(old); err != nil {
		t.Fatal(err)
	}
	if err := s.g.aliceS.SetNextCommitAADForTest(ad); err != nil {
		t.Fatal(err)
	}
	commit, _, _, err := s.g.aliceS.CommitReplaceMembersVerified(
		[]uint32{old[0].Index}, [][]byte{s.bob2KP}, trustAll{})
	if err != nil {
		t.Fatalf("the unchecking member could not build the replace: %v", err)
	}
	return commit
}

// carolReceives applies the Commit as the other tests in this package do,
// without the handshake log's epoch bookkeeping, which is not under test.
func (s succession) carolReceives(commit []byte) (chatstate.ReceiveResult, error) {
	return s.carolStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: 10, Message: commit},
		mls.NewCipher(s.carolS, s.carol.verifier()))
}

func encode(t *testing.T, hs ...chatstate.LeafHandover) []byte {
	t.Helper()
	ev := proto.MLSCommitEvidence{}
	for _, h := range hs {
		ev.Handovers = append(ev.Handovers, h.Wire())
	}
	ad, err := ev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// The refusals: no handover, data that is not a handover, a handover the new
// leaf signed itself, and a genuine handover for another new leaf. Each
// blocks Carol at that epoch (unauthorized_commit, naming Alice); the record
// is not written, so the Commit is not applied.
func TestSuccession_AReceiverRefusesAnUnapprovedTakeover(t *testing.T) {
	for name, ad := range map[string]func(*testing.T, succession) []byte{
		"no handover":    func(*testing.T, succession) []byte { return nil },
		"not a handover": func(*testing.T, succession) []byte { return []byte(`{"v":1,"handovers":[]}`) },
		"signed by bob2": func(t *testing.T, s succession) []byte {
			h := s.signedHandover(t, s.decl)
			leaf, _, err := keychain.GetMLSLeafKey(s.bob2.store)
			if err != nil {
				t.Fatal(err)
			}
			h.Signature = ed25519Sign(leaf.SecretKey, chatstate.LeafHandoverCanonical(h))
			return encode(t, h)
		},
		"for another new leaf": func(t *testing.T, s succession) []byte {
			bob3 := sameAccount(t, s.bob)
			other := bob3.declare(t, "d3333333-3333-4333-8333-333333333333", proto.MLSLeafReasonRotate, time.Now().Unix()+120)
			return encode(t, s.signedHandover(t, other))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSuccession(t)
			_, err := s.carolReceives(s.craft(t, ad(t, s)))
			var blocked *chatstate.SyncBlockedError
			if !errors.As(err, &blocked) || blocked.Block.Cause != chatstate.SyncBlockUnauthorizedCommit ||
				blocked.Block.CommitterAccountID != accountA {
				t.Fatalf("receive = %v; want an unauthorized_commit block naming alice", err)
			}
			// Not a latch (N3): the group is still there, at the epoch it
			// was on, and nothing new is sent on it.
			if _, err := s.carolStore.LoadGroupState(conv, noWatermark); err != nil {
				t.Fatalf("carol's group after the refusal: %v", err)
			}
		})
	}
}

// With Bob's old device's handover in the Commit, Carol applies it: Bob's old
// leaf is gone and Bob2's is in, under the same account.
func TestSuccession_AReceiverAppliesAnApprovedTakeover(t *testing.T) {
	s := newSuccession(t)
	if _, err := s.carolReceives(s.craft(t, encode(t, s.signedHandover(t, s.decl)))); err != nil {
		t.Fatalf("receive = %v", err)
	}
	roster, err := s.carolS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	devices := map[string]bool{}
	for _, l := range roster {
		if a, d, _ := mls.ParseCredentialIdentity(l.Identity); a == accountB {
			devices[d] = true
		}
	}
	if !devices[device2] || devices[device1] || len(devices) != 1 {
		t.Fatalf("bob's leaves after the takeover = %v", devices)
	}
}

func ed25519Sign(secret []byte, message string) []byte {
	return ed25519.Sign(ed25519.PrivateKey(secret), []byte(message))
}
