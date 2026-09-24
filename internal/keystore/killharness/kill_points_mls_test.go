//go:build mls && cgo

package killharness

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func row(c *conversation, ciphertextB64 string) proto.MLSDisplayMessage {
	return proto.MLSDisplayMessage{Seq: c.nextSeq(), CiphertextB64: ciphertextB64}
}

func assertOnce(t *testing.T, got displayed, want string, fromHistory bool) {
	t.Helper()
	if len(got.Items) != 1 || got.Items[0].State != proto.MLSDisplayItemStateShown ||
		text(t, got.PlaintextB64[0]) != want || got.Items[0].FromHistory != fromHistory {
		t.Fatalf("display = %+v; want %q shown (from_history=%v)", got, want, fromHistory)
	}
}

func assertReady(t *testing.T, p *keeperProc, epoch uint64) {
	t.Helper()
	got := p.status()
	if got.NeedsRekey || got.CommitPending || !got.HasGroupState || got.Epoch != epoch {
		t.Fatalf("status = %+v; want ready at epoch %d", got, epoch)
	}
}

// Killed after the AEAD and before write 2: a ciphertext existed only in
// memory, and write 1's intent says its position was taken. After the
// restart the position is burned, never handed out again, and the same
// client message id encrypts afresh at a later one.
func TestKeeperKilledAfterTheSealDoesNotReuseThePosition(t *testing.T) {
	c := newConversation(t)
	seen := positions{}
	a := c.alice.start("", 0)
	seen.add(t, a.encrypt(messageID(1), 1, "before"))
	a.in.Close()
	<-a.done

	victim := c.alice.start(chatstate.CrashSendAfterSeal, 0)
	victim.parkAt(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "lost in memory"))
	ceiling := c.alice.anchor().ReservedBefore
	victim.killAndAssertKilled()

	a = c.alice.start("", 0)
	assertReady(t, a, 1)
	again := a.encrypt(messageID(2), 1, "lost in memory")
	if !again.Created || again.Generation < ceiling {
		t.Fatalf("resend after the kill = %+v; the killed send reserved below %d", again, ceiling)
	}
	seen.add(t, again)
	next := a.encrypt(messageID(3), 1, "after")
	if next.Generation <= again.Generation {
		t.Fatalf("generation went from %d to %d", again.Generation, next.Generation)
	}
	seen.add(t, next)
	if got := c.alice.anchor(); got.ReservedBefore < next.Generation+1 {
		t.Fatalf("anchor ceiling %d is below a position in use (%d)", got.ReservedBefore, next.Generation)
	}

	b := c.bob.start("", 0)
	assertOnce(t, b.decrypt(row(c, again.CiphertextB64)), "lost in memory", false)
	assertOnce(t, b.decrypt(row(c, next.CiphertextB64)), "after", false)
}

// Killed once write 2 is on disk and before the answer left: the app never
// saw the ciphertext. After the restart the outbox gives it back with its
// whole position and no plaintext, a retransmission is the same bytes, and a
// reader shows the message once.
func TestKeeperKilledAfterWriteTwoHandsBackTheSameCiphertext(t *testing.T) {
	c := newConversation(t)
	victim := c.alice.start(chatstate.CrashSendAfterWrite, 0)
	victim.parkAt(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "posted later"))
	victim.killAndAssertKilled()

	a := c.alice.start("", 0)
	assertReady(t, a, 1)
	stored := a.readOutbox(messageID(1))
	retry := a.encrypt(messageID(1), 1, "posted later")
	if retry.Created || retry.CiphertextB64 != stored.CiphertextB64 ||
		retry.Generation != stored.ChainIndex || retry.LeafIndex != stored.LeafIndex ||
		retry.ContentType != stored.ContentType {
		t.Fatalf("retry = %+v; outbox = %+v", retry, stored)
	}
	b := c.bob.start("", 0)
	message := row(c, stored.CiphertextB64)
	assertOnce(t, b.decrypt(message), "posted later", false)
	assertOnce(t, b.decrypt(message), "posted later", true)
}

// Killed between the state file and the anchor: the file is one generation
// ahead of the keyring, the harmless direction. The next load accepts it, the
// next write carries the anchor up, nothing latches and nothing is handed out
// twice.
func TestKeeperKilledBetweenTheFileAndTheAnchorContinues(t *testing.T) {
	c := newConversation(t)
	seen := positions{}
	// The send's second write: write 1 is the first pass through the point.
	victim := c.alice.start(chatstate.CrashCommitAfterFile, 1)
	victim.parkAt(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "file first"))
	behind := c.alice.anchor()
	victim.killAndAssertKilled()

	a := c.alice.start("", 0)
	assertReady(t, a, 1)
	stored := a.readOutbox(messageID(1))
	seen.add(t, proto.MLSEncryptResponseData{Epoch: stored.Epoch, LeafIndex: stored.LeafIndex,
		ContentType: stored.ContentType, Generation: stored.ChainIndex, CiphertextB64: stored.CiphertextB64})
	next := a.encrypt(messageID(2), 1, "second")
	if next.Generation <= stored.ChainIndex {
		t.Fatalf("generation %d after %d", next.Generation, stored.ChainIndex)
	}
	seen.add(t, next)
	// The killed write, then this send's two: the anchor is carried past all.
	if got := c.alice.anchor(); got.Generation != behind.Generation+3 {
		t.Fatalf("anchor generation %d after the next write; the kill left it at %d",
			got.Generation, behind.Generation)
	}
	b := c.bob.start("", 0)
	assertOnce(t, b.decrypt(row(c, stored.CiphertextB64)), "file first", false)
	assertOnce(t, b.decrypt(row(c, next.CiphertextB64)), "second", false)
}

// Killed after a display batch was opened and before it was written: the
// keys it used are still on disk, so the restart opens both messages as
// first deliveries, once, and a re-read comes from the local history.
func TestKeeperKilledMidReceiveBatchOpensEachMessageOnce(t *testing.T) {
	c := newConversation(t)
	a := c.alice.start("", 0)
	one, two := a.encrypt(messageID(1), 1, "one"), a.encrypt(messageID(2), 1, "two")
	rows := []proto.MLSDisplayMessage{row(c, one.CiphertextB64), row(c, two.CiphertextB64)}

	victim := c.bob.start(chatstate.CrashReceiveBatchAfterOpen, 0)
	victim.parkAt(proto.MLSDecryptBatchForAppDisplay, c.bob.decryptRequest(rows...))
	victim.killAndAssertKilled()

	b := c.bob.start("", 0)
	assertReady(t, b, 1)
	for _, fromHistory := range []bool{false, true} {
		got := b.decrypt(rows...)
		if len(got.Items) != 2 || text(t, got.PlaintextB64[0]) != "one" || text(t, got.PlaintextB64[1]) != "two" ||
			got.Items[0].FromHistory != fromHistory || got.Items[1].FromHistory != fromHistory {
			t.Fatalf("batch (from_history=%v) = %+v", fromHistory, got)
		}
	}
}

// Killed after somebody else's Commit was applied in memory: nothing was
// written, so the restart is still on the old epoch and applies the Commit
// once. A second delivery of the row is refused, not applied twice.
func TestKeeperKilledMidProcessAppliesTheCommitOnce(t *testing.T) {
	c := newConversation(t)
	a := c.alice.start("", 0)
	update := a.buildUpdate(c.alice.nextCommitID(), 1)
	a.must(proto.MLSCommitConfirm, c.alice.confirmRequest(update.ClientCommitID), nil)
	seq := c.nextSeq()

	victim := c.bob.start(chatstate.CrashProcessAfterApply, 0)
	victim.parkAt(proto.MLSProcess, c.bob.processRequest(seq, 2, update.CommitB64))
	victim.killAndAssertKilled()

	b := c.bob.start("", 0)
	assertReady(t, b, 1)
	var applied proto.MLSProcessResponseData
	b.must(proto.MLSProcess, c.bob.processRequest(seq, 2, update.CommitB64), &applied)
	if applied.Epoch != 2 {
		t.Fatalf("process after the kill = %+v", applied)
	}
	b.refused(proto.MLSProcess, c.bob.processRequest(seq, 2, update.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	assertReady(t, b, 2)
	assertOnce(t, b.decrypt(row(c, a.encrypt(messageID(1), 2, "epoch two").CiphertextB64)), "epoch two", false)
}

// Killed after this device's own Commit was promoted in memory: the record
// still holds it pending on the old epoch, a confirm settles it once, and a
// second confirm finds nothing to settle.
func TestKeeperKilledMidConfirmKeepsTheCommitPendingUntilSettled(t *testing.T) {
	c := newConversation(t)
	a := c.alice.start("", 0)
	update := a.buildUpdate(c.alice.nextCommitID(), 1)
	a.in.Close()
	<-a.done

	victim := c.alice.start(chatstate.CrashConfirmAfterApply, 0)
	victim.parkAt(proto.MLSCommitConfirm, c.alice.confirmRequest(update.ClientCommitID))
	victim.killAndAssertKilled()

	a = c.alice.start("", 0)
	got := a.status()
	if !got.CommitPending || got.PendingClientCommitID != update.ClientCommitID || got.Epoch != 1 || got.NeedsRekey {
		t.Fatalf("status after the kill = %+v", got)
	}
	a.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "not yet"), proto.ChatMLSErrorCodeCommitPending)
	a.must(proto.MLSCommitConfirm, c.alice.confirmRequest(update.ClientCommitID), nil)
	assertReady(t, a, 2)
	a.refused(proto.MLSCommitConfirm, c.alice.confirmRequest(update.ClientCommitID), proto.ChatStateErrorCodeConflict)

	b := c.bob.start("", 0)
	b.must(proto.MLSProcess, c.bob.processRequest(c.nextSeq(), 2, update.CommitB64), nil)
	assertOnce(t, b.decrypt(row(c, a.encrypt(messageID(2), 2, "settled").CiphertextB64)), "settled", false)
}

// The state directory restored from before the last sends, with the keyring
// left as it is: the latch a rewind requires. Nothing is encrypted on it.
func TestKeeperWithARestoredStateDirectoryLatches(t *testing.T) {
	c := newConversation(t)
	backup := filepath.Join(t.TempDir(), "chat-state")
	if out, err := exec.Command("cp", "-Rp", c.alice.stateRoot(), backup).CombinedOutput(); err != nil {
		t.Fatalf("backup: %v %s", err, out)
	}
	a := c.alice.start("", 0)
	a.encrypt(messageID(1), 1, "after the backup")
	a.in.Close()
	<-a.done

	if err := os.RemoveAll(c.alice.stateRoot()); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cp", "-Rp", backup, c.alice.stateRoot()).CombinedOutput(); err != nil {
		t.Fatalf("restore: %v %s", err, out)
	}
	a = c.alice.start("", 0)
	got := a.status()
	if !got.NeedsRekey || got.RekeyCause != proto.ChatStateRekeyCauseRollback {
		t.Fatalf("status of a restored directory = %+v", got)
	}
	a.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "never"), proto.ChatStateErrorCodeRekeyRequired)
}

// Two Keeper processes of one device on one conversation. One is parked
// inside a send, holding the conversation lock; the other's send waits for
// the lock and refuses with CHAT_STATE_LOCK_TIMEOUT having taken nothing.
// Once the first is killed the second sends, at a position the first never
// reached.
func TestTwoKeeperProcessesOnOneConversationHaveOneWriter(t *testing.T) {
	c := newConversation(t)
	holder := c.alice.start(chatstate.CrashSendAfterSeal, 0)
	holder.parkAt(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "holder"))
	ceiling := c.alice.anchor().ReservedBefore

	other := c.alice.start("", 0)
	other.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(2), 1, "other"), proto.ChatStateErrorCodeLockTimeout)
	if got := c.alice.anchor().ReservedBefore; got != ceiling {
		t.Fatalf("the refused process moved the ceiling from %d to %d", ceiling, got)
	}

	holder.killAndAssertKilled()
	sent := other.encrypt(messageID(2), 1, "other")
	if sent.Generation < ceiling {
		t.Fatalf("the second process sent at %d, inside the killed holder's reservation below %d",
			sent.Generation, ceiling)
	}
	b := c.bob.start("", 0)
	assertOnce(t, b.decrypt(row(c, sent.CiphertextB64)), "other", false)
}
