//go:build mls && cgo

package mls_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The pins a join stages are on disk before the group state that relies on
// them. The process here dies the moment JoinFromPool returns, before any
// caller could record anything else. Bob's group then holds Alice's leaf, and
// a later leaf of Alice's account carrying another account key is refused as
// a changed key, not taken as a first use. One active device per account, so
// that leaf comes in as Carol's replace of Alice's leaf (a recovered identity
// seated by another member, the one shape that brings in another key of an
// account in the tree without a handover).
func TestACrashAfterTheJoinCannotTOFUADifferentAccountKey(t *testing.T) {
	g := newGroup(t)
	carol := newAccount(t, accountC)
	carolS, _ := g.memberOf(t, carol, device1)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	kps := bob.keyPackagesFor(t, device1, 1)
	bobStore := openStore(t, bob.store, bob.id)
	in, err := g.add(g.alice.verifier(), kps[0])
	if err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)
	if err := bob.session(t).JoinFromPool(bobStore, conv, noWatermark, in.Welcome, bob.verifier(), time.Now()); err != nil {
		t.Fatalf("join: %v", err)
	}
	carolIn, err := carolS.ProcessVerified(in.Commit, carol.verifier())
	if err != nil || carolIn.Epoch != 2 {
		t.Fatalf("carol applies bob's add: %+v, %v", carolIn, err)
	}

	swapped := newAccount(t, accountA)
	now := time.Now().Unix()
	kp := keyPackage(t, forged(t, accountA, device2, func(k ed25519.PublicKey) []byte {
		return payload(t, swapped.sign(t, declarationFor(accountA, device2, k, now, proto.MLSLeafReasonEnroll)), swapped.pem)
	}))
	roster, err := carolS.Roster()
	if err != nil {
		t.Fatal(err)
	}
	var aliceLeaf []mls.Leaf
	for _, l := range roster {
		if a, _, _ := mls.ParseCredentialIdentity(l.Identity); a == accountA {
			aliceLeaf = append(aliceLeaf, l)
		}
	}
	if err := carolS.ApproveRemovalsForTest(aliceLeaf); err != nil {
		t.Fatal(err)
	}
	commit, _, _, err := carolS.CommitReplaceMembersVerified([]uint32{aliceLeaf[0].Index}, [][]byte{kp}, trustAll{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bobStore.Receive(conv, noWatermark, chatstate.ReceiveRequest{Seq: 1, Message: commit},
		mls.NewCipher(bob.session(t), bob.verifier()))
	if !errors.Is(err, mls.ErrLeafUntrusted) {
		t.Fatalf("a leaf of alice's account with another account key = %v; want ErrLeafUntrusted", err)
	}
	pin, found := bob.pinOf(t, accountA)
	if !found || pin.State != keychain.PeerKeyPinStateTOFU || pin.Fingerprint != crypto.AccountKeyFingerprint([]byte(g.alice.pem)) {
		t.Fatalf("bob's pin for alice = %+v, %v; want alice's real key", pin, found)
	}
}

// pinWritesFail is a keyring whose peer key pin writes fail, standing in for
// a process that dies at the pin write.
type pinWritesFail struct{ keychain.SecretStore }

func (s pinWritesFail) Set(service, account, value string) error {
	if strings.HasPrefix(account, config.PeerKeyPinPrefix) {
		return errors.New("pin write failed")
	}
	return s.SecretStore.Set(service, account, value)
}

// The other side of the crash window: a pin that cannot be written stops the
// join before its group state is written, and keeps the pool entry, so the
// retry finds the same Welcome joinable and pins the same key.
func TestAJoinWhosePinCannotBeWrittenWritesNoGroupState(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	kps := bob.keyPackagesFor(t, device1, 1)
	bobStore := openStore(t, bob.store, bob.id)
	in, err := g.add(g.alice.verifier(), kps[0])
	if err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)

	failing := bob.deps
	failing.Store = pinWritesFail{bob.store}
	v := handlers.NewMLSLeafVerifier(failing, bob.id, nil)
	if err := bob.session(t).JoinFromPool(bobStore, conv, noWatermark, in.Welcome, v, time.Now()); err == nil {
		t.Fatal("the join succeeded although its pin could not be written")
	}
	if blob, err := bobStore.LoadGroupState(conv, noWatermark); err != nil || len(blob) != 0 {
		t.Fatalf("the group state was written ahead of its pin: %d bytes, %v", len(blob), err)
	}
	if n := poolSize(t, bobStore); n != 1 {
		t.Fatalf("pool holds %d after the refused join, want the entry kept", n)
	}

	if err := bob.session(t).JoinFromPool(bobStore, conv, noWatermark, in.Welcome, bob.verifier(), time.Now()); err != nil {
		t.Fatalf("retried join: %v", err)
	}
	if pin, found := bob.pinOf(t, accountA); !found || pin.Fingerprint != crypto.AccountKeyFingerprint([]byte(g.alice.pem)) {
		t.Fatalf("bob's pin for alice after the retry = %+v, %v", pin, found)
	}
}
