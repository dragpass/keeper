//go:build mls && cgo

package mls_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A crash between the joined group state and the pool delete leaves the
// KeyPackage's private keys in the pool. The next process to open the pool
// finds the conversation holding the group they were for and deletes them.
func TestAKeyPackageLeftBehindByACrashedJoinIsDeletedOnTheNextPoolOpen(t *testing.T) {
	g := newGroup(t)
	bob := newAccount(t, accountB)
	bob.declare(t, device1, proto.MLSLeafReasonEnroll, time.Now().Unix())
	kps := bob.keyPackagesFor(t, device1, 2)
	bobStore := openStore(t, bob.store, bob.id)
	in, err := g.add(g.alice.verifier(), kps[0])
	if err != nil {
		t.Fatal(err)
	}
	g.confirm(t, in.ClientCommitID)

	crash := errors.New("the process died here")
	restore := mls.StopAfterJoinedStateSavedForTest(crash)
	if err := bob.session(t).JoinFromPool(bobStore, conv, noWatermark, in.Welcome, bob.verifier(), time.Now()); !errors.Is(err, crash) {
		t.Fatalf("join = %v; want it stopped after the state write", err)
	}
	restore()
	if blob, err := bobStore.LoadGroupState(conv, noWatermark); err != nil || len(blob) == 0 {
		t.Fatalf("the joined state was not written before the stop: %v", err)
	}

	later := openStore(t, bob.store, bob.id)
	if n := poolSize(t, later); n != 1 {
		t.Fatalf("pool holds %d after the next open, want only the unused KeyPackage", n)
	}
	refs, err := mls.WelcomeKeyPackageRefsForTest(in.Welcome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := later.LookupKeyPackage(refs, time.Now()); !errors.Is(err, chatstate.ErrKeyPackageNotInPool) {
		t.Fatalf("the consumed KeyPackage's keys are still in the pool: %v", err)
	}
}
