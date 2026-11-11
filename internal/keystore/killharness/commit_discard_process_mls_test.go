//go:build mls && cgo

// mls_commit_discard_refused on the Keeper binary: a refused Commit is
// dropped by a process other than the one that built it, the same intent is
// rebuilt and lands, and a discard that arrives after a sign-out and sign-in
// is refused and leaves the newer session's Commit pending.

package killharness

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// editableKeyring is the device's keyring file as a SecretStore that writes
// back, for a chat sign-in made while no Keeper process runs.
type editableKeyring map[string]string

func (k editableKeyring) Get(service, account string) (string, error) {
	v, ok := k[service+"|"+account]
	if !ok {
		return "", keychain.ErrSecretNotFound
	}
	return v, nil
}
func (k editableKeyring) Set(service, account, value string) error {
	k[service+"|"+account] = value
	return nil
}
func (k editableKeyring) Delete(service, account string) error {
	delete(k, service+"|"+account)
	return nil
}

// signIn commits a chat login in the keyring file. No process may run.
func (d *device) signIn(intent string) string {
	d.t.Helper()
	store := editableKeyring(d.keyringEntries())
	state, err := keychain.ReadChatLogin(store)
	if err != nil {
		d.t.Fatal(err)
	}
	if err := keychain.PrepareChatLogin(store, intent, state.Generation, state.PreparationSequence); err != nil {
		d.t.Fatalf("prepare chat login: %v", err)
	}
	committed, _, err := keychain.CommitChatLogin(store, intent, d.account, "alias")
	if err != nil {
		d.t.Fatalf("commit chat login: %v", err)
	}
	raw, err := json.Marshal(map[string]string(store))
	if err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(d.keyringPath(), raw, 0o600); err != nil {
		d.t.Fatal(err)
	}
	return committed.Generation
}

func (d *device) discardRefusedRequest(id string, epoch uint64) proto.MLSCommitDiscardRefusedRequest {
	return proto.MLSCommitDiscardRefusedRequest{
		Permit: d.permit(), OrgID: hOrg, ConversationID: hConv,
		ClientCommitID: id, ExpectedEpoch: epoch, RefusalCode: "CHAT_MLS_REMOVAL_PENDING",
	}
}

func (p *keeperProc) stop() {
	p.in.Close()
	<-p.done
}

func TestKeeperProcess_ARefusedCommitIsDiscardedOnlyUnderItsOwnSignIn(t *testing.T) {
	tp := newThreeParty(t)
	alice, carol := tp.alice, tp.carol
	alice.signIn("intent-1")

	a := alice.start("", 0)
	refused := alice.nextCommitID()
	a.buildUpdate(refused, 1)
	a.kill()

	// Another process drops it, and the confirmed epoch stays.
	a = alice.start("", 0)
	a.refused(proto.MLSCommitDiscardRefused, alice.discardRefusedRequest(alice.nextCommitID(), 1),
		string(errs.ErrCodeChatStateConflict))
	var discarded proto.MLSCommitDiscardRefusedResponseData
	a.must(proto.MLSCommitDiscardRefused, alice.discardRefusedRequest(refused, 1), &discarded)
	if !discarded.Discarded {
		t.Fatalf("discard = %+v", discarded)
	}
	if st := a.status(); st.CommitPending || st.Epoch != 1 {
		t.Fatalf("status after the discard = %+v", st)
	}
	a.refused(proto.MLSCommitDiscardRefused, alice.discardRefusedRequest(refused, 1),
		string(errs.ErrCodeChatStateConflict))

	// The same intent rebuilt under a new id lands and Carol applies it.
	rebuilt := alice.nextCommitID()
	built := a.buildUpdate(rebuilt, 1)
	a.must(proto.MLSCommitConfirm, alice.confirmRequest(rebuilt), nil)
	c := carol.start("", 0)
	c.must(proto.MLSProcess, carol.processRequest(2, 2, built.CommitB64), nil)
	if st := c.status(); st.Epoch != 2 {
		t.Fatalf("carol after the rebuilt Commit = %+v", st)
	}
	c.stop()

	// A Commit of the earlier sign-in is not discarded after a new one.
	stale := alice.nextCommitID()
	a.buildUpdate(stale, 2)
	a.stop()
	alice.signIn("intent-2")
	a = alice.start("", 0)
	a.refused(proto.MLSCommitDiscardRefused, alice.discardRefusedRequest(stale, 2),
		string(errs.ErrCodeChatStateConflict))
	if st := a.status(); !st.CommitPending || st.PendingClientCommitID != stale || st.Epoch != 2 {
		t.Fatalf("status after the stale discard = %+v", st)
	}
	a.stop()
}
