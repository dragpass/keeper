// Tests for what mls_leaf_promote does to the KeyPackage pool: the previous
// leaf's entries go with the promote, and nothing else.
package handlers

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// seedPool stores count entries minted under leaf, as a generation would.
func (f *chatStateFixture) seedPool(t *testing.T, leaf string, tag byte, count int) [][]byte {
	t.Helper()
	store, err := chatstate.Open(f.deps.Store, leafTestAccountID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var refs [][]byte
	var entries []chatstate.KeyPackagePoolEntry
	for i := 0; i < count; i++ {
		ref := bytes.Repeat([]byte{tag + byte(i)}, 32)
		refs = append(refs, ref)
		entries = append(entries, chatstate.KeyPackagePoolEntry{
			Ref: ref, NotAfter: uint64(f.clock.now().Add(time.Hour).Unix()), Leaf: leaf,
			Private: bytes.Repeat([]byte{0x5a}, 64),
		})
	}
	if err := store.AddKeyPackages(entries, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	return refs
}

func (f *chatStateFixture) poolHolds(t *testing.T, ref []byte) bool {
	t.Helper()
	store, err := chatstate.Open(f.deps.Store, leafTestAccountID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.LookupKeyPackage([][]byte{ref}, f.clock.now())
	return err == nil
}

func TestHandleMLSLeafPromote_DropsThePreviousLeafsKeyPackages(t *testing.T) {
	f := newKeyPackageFixture(t)
	first := f.enrollAccount(t, leafTestAccountID, 0)
	old := f.seedPool(t, first.SignatureKeyFingerprint, 0x10, 3)

	// A pending rotation drops nothing: the old leaf still signs.
	second, accept := f.stageRotation(t)
	if n := f.poolSize(t, leafTestAccountID); n != 3 {
		t.Fatalf("pool holds %d with a rotation pending, want 3", n)
	}
	resp := HandleMLSLeafPromote(f.deps, accept)
	if !resp.Success || !resp.Data.(proto.MLSLeafPromoteResponseData).Promoted {
		t.Fatalf("promote: %+v", resp)
	}
	for _, ref := range old {
		if f.poolHolds(t, ref) {
			t.Fatal("an entry of the previous leaf survived the promote")
		}
	}

	// Entries minted under the new leaf afterwards are not touched by a
	// duplicate promote.
	fresh := f.seedPool(t, second.SignatureKeyFingerprint, 0x20, 2)
	if resp := HandleMLSLeafPromote(f.deps, accept); !resp.Success || resp.Data.(proto.MLSLeafPromoteResponseData).Promoted {
		t.Fatalf("duplicate promote: %+v", resp)
	}
	for _, ref := range fresh {
		if !f.poolHolds(t, ref) {
			t.Fatal("an entry of the new leaf was dropped")
		}
	}
}

// A pool that cannot be written stops the promote before the keyring is
// touched, and the same acceptance promotes once the pool is writable again.
func TestHandleMLSLeafPromote_APoolFailureLeavesNothingHalfDone(t *testing.T) {
	f := newKeyPackageFixture(t)
	first := f.enrollAccount(t, leafTestAccountID, 0)
	old := f.seedPool(t, first.SignatureKeyFingerprint, 0x10, 1)
	second, accept := f.stageRotation(t)

	paths, err := filepath.Glob(filepath.Join(f.root, "*", "key-packages.pool"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("pool file: %v %v", paths, err)
	}
	sealed, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], []byte("DPKP not a pool"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := HandleMLSLeafPromote(f.deps, accept)
	if resp.Success || resp.ErrorCode != string(errs.ErrCodeStorageFailure) {
		t.Fatalf("promote over an unreadable pool: %+v", resp)
	}
	if activeLeafFingerprint(f.deps.Store) != first.SignatureKeyFingerprint {
		t.Fatal("the failed promote changed the active leaf")
	}
	if pending, found, err := keychain.GetMLSLeafPending(f.deps.Store); err != nil || !found {
		t.Fatalf("the failed promote lost the pending leaf: %v", err)
	} else {
		wipeMLSLeafSlots(&pending)
	}

	if err := os.WriteFile(paths[0], sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	resp = HandleMLSLeafPromote(f.deps, accept)
	if !resp.Success || !resp.Data.(proto.MLSLeafPromoteResponseData).Promoted {
		t.Fatalf("the retried promote: %+v", resp)
	}
	if activeLeafFingerprint(f.deps.Store) != second.SignatureKeyFingerprint || f.poolHolds(t, old[0]) {
		t.Fatal("the retried promote did not finish both halves")
	}
}

// A generation parked before its pool write, and a promote started meanwhile.
// The leaf lock makes the promote wait, so it runs after the generation and
// drops what the generation wrote for the old leaf. Without the lock the
// promote would find an empty pool, and the generation would then write the
// old leaf's entries under the new active leaf.
func TestHandleMLSLeafPromote_ARacingGenerationIsDroppedAfterIt(t *testing.T) {
	if !mls.Available() {
		t.Skip("key packages need the MLS library")
	}
	f := newKeyPackageFixture(t)
	first := f.enrollAccount(t, leafTestAccountID, 0)
	second, accept := f.stageRotation(t)

	barrier := &poolWriteBarrier{SecretStore: f.deps.Store, reached: make(chan struct{}), release: make(chan struct{})}
	barrier.armed.Store(true)
	deps := f.deps
	deps.Store = barrier
	req := f.keyPackageRequest(t, 3, "")

	generated := make(chan proto.BaseResponse, 1)
	go func() { generated <- HandleMLSKeyPackageGenerate(deps, req) }()
	select {
	case <-barrier.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the generation never reached its pool write")
	}
	promoted := make(chan proto.BaseResponse, 1)
	go func() { promoted <- HandleMLSLeafPromote(deps, accept) }()
	select {
	case resp := <-promoted:
		promoted <- resp
	case <-time.After(300 * time.Millisecond):
	}
	close(barrier.release)

	deadline := time.After(10 * time.Second)
	var gen, prom proto.BaseResponse
	select {
	case gen = <-generated:
	case <-deadline:
		t.Fatal("the generation did not finish")
	}
	select {
	case prom = <-promoted:
	case <-deadline:
		t.Fatal("the promote did not finish")
	}
	if !gen.Success || !prom.Success {
		t.Fatalf("generate: %q, promote: %q", gen.Error, prom.Error)
	}
	if fp := gen.Data.(proto.MLSKeyPackageGenerateResponseData).LeafSignatureKeyFingerprint; fp != first.SignatureKeyFingerprint {
		t.Fatalf("the generation built for %s, want the old leaf", fp)
	}
	if activeLeafFingerprint(f.deps.Store) != second.SignatureKeyFingerprint {
		t.Fatal("the promote did not take effect")
	}
	if n := f.poolSize(t, leafTestAccountID); n != 0 {
		t.Fatalf("pool holds %d entries of the old leaf after the promote", n)
	}
}
