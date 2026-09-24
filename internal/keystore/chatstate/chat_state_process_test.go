// chat_state_process_test.go — the guards that only real processes can give.
//
// A mock cannot show that two Keeper processes do not hand out the same chain
// position, and a fake cannot show what a SIGKILL leaves on disk. Both are the
// failures this package exists to prevent, so both are tested with actual
// processes: the test binary re-executes itself as a helper, the parent
// coordinates through barrier files, and Process.Kill() is a real kill.
//
// **What Process.Kill() means on each platform, since it is not one thing.** On
// unix it is SIGKILL. On Windows it is TerminateProcess, which also stops the
// process without running deferred functions, atexit handlers, or any flush of
// user-space buffers — so for what these tests assert, namely what an
// interrupted write leaves on disk, the two are equivalent and the Windows runs
// are not weaker. The progress file is written with unbuffered append syscalls
// for that reason: a line that exists was really handed out, on both platforms.
// Two differences are real and neither is skipped here. TerminateProcess is
// asynchronous, so every kill is followed by waiting on the child rather than
// assuming it is already gone. And the lock is mandatory on Windows
// (LockFileEx) against advisory on unix (flock), with the handle released by
// the kernel after termination rather than by the dying process; the tests
// below take the next round's lock after each kill, so a release that never
// came would surface as a lock timeout instead of passing quietly. **How long
// that release takes is still unmeasured** and stays on the ADR §4.5 list — the
// tests show it happens, not that it happens within any particular bound.
//
// The structure follows personal_key_bundle_process_test.go, which already
// proves the shape on this codebase: helper mode behind an env var, a barrier
// file to release contenders at one moment, a checkpoint file so the parent
// kills at a known point, and one keyring shared by every process.
//
// The shared keyring here is a file-backed SecretStore rather than keychain's
// e2e mirror, because that mirror rewrites its whole JSON file in place on
// every Set and a SIGKILL in the middle of one truncates it. The store below
// replaces the file the same way this package replaces a record — temp file,
// rename — so the only thing the kills in these tests damage is the state under
// test. Nothing in this package branches on the store type, and the blocked
// assertions below are what prove the file lock is still on the path.

//go:build darwin || linux || windows

package chatstate

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
)

const (
	helperModeEnv  = "DRAGPASS_TEST_CHAT_STATE_HELPER"
	helperReadyEnv = "DRAGPASS_TEST_CHAT_STATE_READY"
	helperRelease  = "DRAGPASS_TEST_CHAT_STATE_RELEASE"
	helperCheckpnt = "DRAGPASS_TEST_CHAT_STATE_CHECKPOINT"
	helperProgress = "DRAGPASS_TEST_CHAT_STATE_PROGRESS"
	helperCount    = "DRAGPASS_TEST_CHAT_STATE_COUNT"
	helperClientID = "DRAGPASS_TEST_CHAT_STATE_CLIENT_ID"
	helperKeyring  = "DRAGPASS_TEST_CHAT_STATE_KEYRING"
	helperDelayMs  = "DRAGPASS_TEST_CHAT_STATE_DELAY_MS"
)

type childResult struct {
	output string
	err    error
}

// ────────────────────────────────────────────────────────────────────────
// Helper process.
// ────────────────────────────────────────────────────────────────────────

func TestChatStateProcessHelper(t *testing.T) {
	mode := os.Getenv(helperModeEnv)
	if mode == "" {
		return
	}
	store, err := Open(mirroredSecretStore{path: os.Getenv(helperKeyring)}, testOwner)
	if err != nil {
		fmt.Printf("error: open store: %v\n", err)
		return
	}
	defer store.Close()

	signalReady := func() bool {
		if err := os.WriteFile(os.Getenv(helperReadyEnv), []byte("ready"), 0o600); err != nil {
			fmt.Printf("error: signal ready: %v\n", err)
			return false
		}
		return true
	}

	switch mode {
	case "holder":
		paths := store.paths(testConvA)
		if err := os.MkdirAll(paths.dir, 0o700); err != nil {
			fmt.Printf("error: create state directory: %v\n", err)
			return
		}
		release, err := acquireConversationLock(paths.lock, LockTimeout)
		if err != nil {
			fmt.Printf("error: acquire lock: %v\n", err)
			return
		}
		defer release()
		if !signalReady() {
			return
		}
		if err := waitForFile(os.Getenv(helperRelease)); err != nil {
			fmt.Printf("error: wait for release: %v\n", err)
			return
		}
		fmt.Print("released\n")

	case "timeout":
		store.lockTimeout = 100 * time.Millisecond
		if !signalReady() {
			return
		}
		_, err := store.Reserve(testConvA, 1, noWatermark)
		if errors.Is(err, ErrLockTimeout) {
			fmt.Print("timeout\n")
			return
		}
		fmt.Printf("error: contended reserve = %v\n", err)

	case "reserve":
		if !signalReady() {
			return
		}
		count, _ := strconv.Atoi(os.Getenv(helperCount))
		reservation, err := store.Reserve(testConvA, count, noWatermark)
		if errors.Is(err, ErrRekeyRequired) {
			fmt.Print("rekey-required\n")
			return
		}
		if err != nil {
			fmt.Printf("error: reserve: %v\n", err)
			return
		}
		fmt.Printf("reserved:%d:%d:%d\n",
			reservation.FirstChainIndex, reservation.Count, reservation.Generation)

	case "crash-after-reserve":
		if !signalReady() {
			return
		}
		reservation, err := store.Reserve(testConvA, 1, noWatermark)
		if err != nil {
			fmt.Printf("error: reserve: %v\n", err)
			return
		}
		// The position is durable now and the ciphertext does not exist yet.
		// This is the window the ADR calls the only irreversible one, so the
		// kill lands exactly here.
		if err := os.WriteFile(
			os.Getenv(helperCheckpnt),
			[]byte(strconv.FormatUint(reservation.FirstChainIndex, 10)),
			0o600,
		); err != nil {
			fmt.Printf("error: checkpoint: %v\n", err)
			return
		}
		time.Sleep(30 * time.Second)

	case "hammer":
		if !signalReady() {
			return
		}
		progress, err := os.OpenFile(os.Getenv(helperProgress), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Printf("error: open progress: %v\n", err)
			return
		}
		for {
			reservation, err := store.Reserve(testConvA, 1, noWatermark)
			if err != nil {
				fmt.Printf("error: reserve: %v\n", err)
				return
			}
			if _, err := fmt.Fprintf(progress, "%d\n", reservation.FirstChainIndex); err != nil {
				return
			}
			_ = progress.Sync()
		}

	case "send":
		if !signalReady() {
			return
		}
		reservation, err := store.Reserve(testConvA, 1, noWatermark)
		if err != nil {
			fmt.Printf("error: reserve: %v\n", err)
			return
		}
		entry := OutboxEntry{
			ClientMessageID: os.Getenv(helperClientID),
			Position:        Position{Epoch: reservation.Epoch, Generation: reservation.FirstChainIndex},
			IV:              bytes.Repeat([]byte{9}, ivBytes),
		}
		entry.Ciphertext = []byte("ciphertext-at-" + strconv.FormatUint(reservation.FirstChainIndex, 10))
		stored, created, err := store.CommitOutbox(testConvA, noWatermark, entry)
		if err != nil {
			fmt.Printf("error: commit outbox: %v\n", err)
			return
		}
		fmt.Printf("sent:%d:%t:%s\n", stored.Position.Generation, created,
			base64.StdEncoding.EncodeToString(stored.Ciphertext))

	case "tc-send":
		if !signalReady() {
			return
		}
		cipher := &fakeCipher{}
		// A delay between the peek and the AEAD widens the window T-c has to
		// cover. Without the lock spanning it, a second process loads the same
		// state in here and both encrypt at the same position.
		if ms, _ := strconv.Atoi(os.Getenv(helperDelayMs)); ms > 0 {
			cipher.beforeAt = func() { time.Sleep(time.Duration(ms) * time.Millisecond) }
		}
		clientID := os.Getenv(helperClientID)
		result, err := store.Send(testConvA, noWatermark, SendRequest{
			ClientMessageID: clientID,
			Plaintext:       []byte("plaintext for " + clientID),
		}, cipher)
		if err != nil {
			fmt.Printf("error: tc send: %v\n", err)
			return
		}
		fmt.Printf("tc-sent:%d:%t:%s\n", result.Entry.Position.Generation, result.Created,
			base64.StdEncoding.EncodeToString(result.Entry.Ciphertext))

	case "tc-crash-mid-send":
		if !signalReady() {
			return
		}
		cipher := &fakeCipher{}
		cipher.beforeAt = func() {
			// Here the intent is fsynced and the AEAD has not run. This is the
			// window T-c leaves open, so the kill lands exactly in it.
			position, err := cipher.Peek()
			if err != nil {
				fmt.Printf("error: peek: %v\n", err)
				return
			}
			if err := os.WriteFile(
				os.Getenv(helperCheckpnt),
				[]byte(strconv.FormatUint(position.Generation, 10)),
				0o600,
			); err != nil {
				fmt.Printf("error: checkpoint: %v\n", err)
				return
			}
			time.Sleep(30 * time.Second)
		}
		if _, err := store.Send(testConvA, noWatermark, SendRequest{
			ClientMessageID: os.Getenv(helperClientID),
			Plaintext:       []byte("never reaches the wire"),
		}, cipher); err != nil {
			fmt.Printf("error: tc crash send: %v\n", err)
		}

	case "tc-receive":
		if !signalReady() {
			return
		}
		seq, _ := strconv.ParseUint(os.Getenv(helperCount), 10, 64)
		got, err := store.Receive(testConvA, noWatermark,
			ReceiveRequest{Seq: seq, Message: []byte("wire")}, inbound(3, uint32(seq), "delivered"))
		if err != nil {
			fmt.Printf("error: tc receive: %v\n", err)
			return
		}
		fmt.Printf("tc-received:%t:%t\n", got.FirstDelivery, got.FromHistory)

	case "tc-crash-mid-receive":
		if !signalReady() {
			return
		}
		seq, _ := strconv.ParseUint(os.Getenv(helperCount), 10, 64)
		cipher := inbound(3, uint32(seq), "delivered")
		cipher.beforeState = func() {
			// The decrypt has happened and nothing has been written. If the
			// mark and the sealed copy were separate writes, this is where a
			// kill would leave one without the other.
			if err := os.WriteFile(os.Getenv(helperCheckpnt), []byte("opened"), 0o600); err != nil {
				fmt.Printf("error: checkpoint: %v\n", err)
				return
			}
			time.Sleep(30 * time.Second)
		}
		if _, err := store.Receive(testConvA, noWatermark,
			ReceiveRequest{Seq: seq, Message: []byte("wire")}, cipher); err != nil {
			fmt.Printf("error: tc crash receive: %v\n", err)
		}

	case "commit-crash":
		if !signalReady() {
			return
		}
		if _, err := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
			ClientCommitID: os.Getenv(helperClientID),
			Plan:           CommitPlan{AddKeyPackages: [][]byte{[]byte("a key package")}, UserInitiated: true},
		}, &fakeCommitter{}); err != nil {
			fmt.Printf("error: begin commit: %v\n", err)
			return
		}
		// The commit is built, durable and posted, and no verdict has come
		// back. This is §7.3.2's third outcome, so the kill lands here.
		if err := os.WriteFile(os.Getenv(helperCheckpnt), []byte("pending"), 0o600); err != nil {
			fmt.Printf("error: checkpoint: %v\n", err)
			return
		}
		time.Sleep(30 * time.Second)

	case "commit-gates":
		if !signalReady() {
			return
		}
		_, commitErr := store.BeginCommit(testConvA, noWatermark, BeginCommitRequest{
			ClientCommitID: "99999999-9999-4999-8999-999999999999",
		}, &fakeCommitter{})
		_, sendErr := store.Send(testConvA, noWatermark, SendRequest{
			ClientMessageID: testClientA,
			Plaintext:       []byte("not while the epoch is undecided"),
		}, &fakeCipher{})
		pending, found, pendingErr := store.PendingCommit(testConvA, noWatermark)
		if pendingErr != nil {
			fmt.Printf("error: pending commit: %v\n", pendingErr)
			return
		}
		fmt.Printf("commit-gates:%t:%t:%t:%t:%s\n",
			errors.Is(commitErr, ErrCommitPending),
			errors.Is(sendErr, ErrCommitPending),
			found, pending.Welcome == nil, pending.ClientCommitID)

	case "commit-confirm":
		if !signalReady() {
			return
		}
		out, err := store.ConfirmCommit(testConvA, noWatermark, CommitOutcome{
			ClientCommitID: os.Getenv(helperClientID),
			Kind:           CommitAccepted,
		}, &fakeCommitter{})
		if err != nil {
			fmt.Printf("error: confirm commit: %v\n", err)
			return
		}
		fmt.Printf("commit-confirmed:%d:%t\n", out.Epoch, out.WelcomeReleasable)

	case "resend":
		if !signalReady() {
			return
		}
		entry, err := store.ReadOutbox(testConvA, noWatermark, os.Getenv(helperClientID))
		if errors.Is(err, ErrNotFound) {
			fmt.Print("outbox-miss\n")
			return
		}
		if err != nil {
			fmt.Printf("error: read outbox: %v\n", err)
			return
		}
		fmt.Printf("resent:%d:%s\n", entry.Position.Generation,
			base64.StdEncoding.EncodeToString(entry.Ciphertext))

	default:
		fmt.Printf("error: unknown helper mode %q\n", mode)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Two processes, one conversation.
// ────────────────────────────────────────────────────────────────────────

// TestChatStateReserveSerializesAcrossProcesses is the user-specified two
// subprocess test. A holder takes the conversation lock, two contenders reach
// the reserve call, and both are confirmed blocked before the holder lets go.
//
// The blocked assertion is also what proves the file lock is on the path: if
// the lock were skipped for any reason, both contenders would finish while the
// holder still held it and this test would fail before any of the rest is
// checked.
func TestChatStateReserveSerializesAcrossProcesses(t *testing.T) {
	env := newProcessEnv(t)

	holder, holderDone := env.start(t, "holder", "holder-ready",
		helperRelease+"="+filepath.Join(env.tempDir, "release"))
	env.waitReady(t, "holder-ready")

	firstCmd, firstDone := env.start(t, "reserve", "first-ready", helperCount+"=2")
	secondCmd, secondDone := env.start(t, "reserve", "second-ready", helperCount+"=3")
	env.waitReady(t, "first-ready")
	env.waitReady(t, "second-ready")

	assertChildBlocked(t, firstDone)
	assertChildBlocked(t, secondDone)

	if err := os.WriteFile(filepath.Join(env.tempDir, "release"), []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := waitForChild(t, holder, holderDone); !strings.Contains(out.output, "released") {
		t.Fatalf("holder: output=%q err=%v", out.output, out.err)
	}

	firstRange := parseReserved(t, waitForChild(t, firstCmd, firstDone))
	secondRange := parseReserved(t, waitForChild(t, secondCmd, secondDone))

	// Disjoint ranges. Two processes consuming one position is the key-reuse
	// failure; this is the assertion that says it did not happen.
	low, high := firstRange, secondRange
	if low.first > high.first {
		low, high = high, low
	}
	if low.first != 0 || low.first+uint64(low.count) != high.first {
		t.Fatalf("overlapping or gapped ranges: %+v then %+v", low, high)
	}
	if firstRange.generation == secondRange.generation {
		t.Fatalf("both reservations committed generation %d", firstRange.generation)
	}

	rec := env.readRecord(t)
	if rec.NextIndex != 5 {
		t.Fatalf("final next_index = %d, want 5 (one writer overwrote the other)", rec.NextIndex)
	}
	if rec.Generation != 2 {
		t.Fatalf("final generation = %d, want 2", rec.Generation)
	}
}

// A contended send closes with a distinguishable failure instead of waiting for
// a rotation-sized ceiling or, worse, proceeding without the lock.
func TestChatStateReserveLockTimesOut(t *testing.T) {
	env := newProcessEnv(t)

	holder, holderDone := env.start(t, "holder", "holder-ready",
		helperRelease+"="+filepath.Join(env.tempDir, "release"))
	env.waitReady(t, "holder-ready")

	contender, contenderDone := env.start(t, "timeout", "timeout-ready")
	env.waitReady(t, "timeout-ready")
	result := waitForChild(t, contender, contenderDone)
	if !strings.Contains(result.output, "timeout") {
		t.Fatalf("contender: output=%q err=%v", result.output, result.err)
	}

	if err := os.WriteFile(filepath.Join(env.tempDir, "release"), []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := waitForChild(t, holder, holderDone); !strings.Contains(out.output, "released") {
		t.Fatalf("holder: output=%q err=%v", out.output, out.err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// SIGKILL.
// ────────────────────────────────────────────────────────────────────────

// A process killed between "the position is spent" and "the ciphertext exists"
// must lose the message, never the position. Handing that index out again would
// encrypt a second plaintext under the same (key, nonce).
func TestChatStateAbandonsAPositionAfterAKill(t *testing.T) {
	env := newProcessEnv(t)
	checkpoint := filepath.Join(env.tempDir, "reserved-index")

	victim, victimDone := env.start(t, "crash-after-reserve", "crash-ready",
		helperCheckpnt+"="+checkpoint)
	env.waitReady(t, "crash-ready")
	env.waitReady(t, "reserved-index")

	raw, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	killed, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := victim.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if result := waitForChild(t, victim, victimDone); result.err == nil {
		t.Fatalf("the killed child exited cleanly: %q", result.output)
	}

	next, nextDone := env.start(t, "reserve", "next-ready", helperCount+"=1")
	env.waitReady(t, "next-ready")
	got := parseReserved(t, waitForChild(t, next, nextDone))
	if got.first <= killed {
		t.Fatalf("index %d was handed out again after the kill (killed at %d)", got.first, killed)
	}

	// The abandoned position carries no ciphertext, so nothing can retransmit
	// under it either.
	store := env.parentStore(t)
	defer store.Close()
	rec, err := store.readRecord(store.paths(testConvA), testConvA)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if rec.positionTaken(Position{Generation: killed}) {
		t.Fatalf("the abandoned position %d carries an outbox entry", killed)
	}
}

// Killing a process in the middle of a stream of writes must leave the previous
// record or the new one, never a mixture, and must never re-issue a position
// the dead process already logged.
func TestChatStateSurvivesKillsDuringTheWriteLoop(t *testing.T) {
	env := newProcessEnv(t)
	progress := filepath.Join(env.tempDir, "progress")

	highest := uint64(0)
	lines := 0
	for round := range 5 {
		ready := fmt.Sprintf("hammer-ready-%d", round)
		hammer, hammerDone := env.start(t, "hammer", ready, helperProgress+"="+progress)
		env.waitReady(t, ready)
		// Kill only once the child has demonstrably completed a reservation and
		// is therefore inside the loop. This used to be a 60ms sleep, which is
		// not a portable way to say "it has started": one cycle is two anchor
		// writes plus an fsync and a rename, and on Windows CI that costs more
		// than 60ms, so the kill landed before the first position was ever
		// logged and the run failed on an empty progress file. The child loops
		// straight into the next reservation after appending a line, so a kill
		// issued here still lands mid-cycle.
		lines = waitForLoggedLines(t, progress, lines+1)
		if err := hammer.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		waitForChild(t, hammer, hammerDone)

		logged := highestLogged(t, progress)
		if logged < highest {
			t.Fatalf("progress went backwards: %d after %d", logged, highest)
		}
		highest = logged

		store := env.parentStore(t)
		rec, err := store.readRecord(store.paths(testConvA), testConvA)
		if err != nil {
			store.Close()
			t.Fatalf("round %d: the record did not load after the kill: %v", round, err)
		}
		if rec == nil {
			store.Close()
			t.Fatalf("round %d: the record vanished", round)
		}
		// Either the write that was in flight landed or it did not. Anything
		// between those two is a torn state.
		if rec.NextIndex != highest+1 && rec.NextIndex != highest+2 {
			store.Close()
			t.Fatalf("round %d: next_index = %d, want %d or %d",
				round, rec.NextIndex, highest+1, highest+2)
		}
		leftovers := tempFilesIn(t, store.paths(testConvA).dir)
		store.Close()
		if len(leftovers) > 0 {
			t.Fatalf("round %d: a read left temp files behind: %v", round, leftovers)
		}
	}

	next, nextDone := env.start(t, "reserve", "after-hammer", helperCount+"=1")
	env.waitReady(t, "after-hammer")
	got := parseReserved(t, waitForChild(t, next, nextDone))
	if got.first <= highest {
		t.Fatalf("index %d was re-issued after the kills (highest logged %d)", got.first, highest)
	}
}

// ────────────────────────────────────────────────────────────────────────
// Retransmission and rollback across restarts.
// ────────────────────────────────────────────────────────────────────────

// A retransmission from a different process sends the bytes the first process
// stored. Re-encrypting would move the chain and produce a second ciphertext
// for one message.
func TestChatStateRetransmitReusesTheStoredCiphertext(t *testing.T) {
	env := newProcessEnv(t)

	sender, senderDone := env.start(t, "send", "send-ready", helperClientID+"="+testClientA)
	env.waitReady(t, "send-ready")
	sent := waitForChild(t, sender, senderDone)
	sentIndex, sentBytes := parseSent(t, sent)

	resender, resenderDone := env.start(t, "resend", "resend-ready", helperClientID+"="+testClientA)
	env.waitReady(t, "resend-ready")
	resentIndex, resentBytes := parseResent(t, waitForChild(t, resender, resenderDone))

	if sentIndex != resentIndex || sentBytes != resentBytes {
		t.Fatalf("retransmission differs: sent %d/%s, resent %d/%s",
			sentIndex, sentBytes, resentIndex, resentBytes)
	}

	store := env.parentStore(t)
	defer store.Close()
	rec, err := store.readRecord(store.paths(testConvA), testConvA)
	if err != nil {
		t.Fatal(err)
	}
	if rec.NextIndex != 1 {
		t.Fatalf("the retransmission consumed a second position: next_index = %d", rec.NextIndex)
	}
}

// Restoring the state file from a snapshot and restarting is the plain backup
// case. The keyring anchor is on a different medium and did not come back with
// it, so the restart is refused rather than continued.
func TestChatStateRefusesARestoredFileAfterRestart(t *testing.T) {
	env := newProcessEnv(t)

	first, firstDone := env.start(t, "reserve", "snap-ready", helperCount+"=1")
	env.waitReady(t, "snap-ready")
	parseReserved(t, waitForChild(t, first, firstDone))

	store := env.parentStore(t)
	recordPath := store.paths(testConvA).record
	store.Close()
	snapshot, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}

	for round := range 3 {
		child, done := env.start(t, "reserve", fmt.Sprintf("more-ready-%d", round), helperCount+"=1")
		env.waitReady(t, fmt.Sprintf("more-ready-%d", round))
		parseReserved(t, waitForChild(t, child, done))
	}

	if err := os.WriteFile(recordPath, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	restarted, restartedDone := env.start(t, "reserve", "restored-ready", helperCount+"=1")
	env.waitReady(t, "restored-ready")
	result := waitForChild(t, restarted, restartedDone)
	if !strings.Contains(result.output, "rekey-required") {
		t.Fatalf("a restored state file was accepted: output=%q err=%v", result.output, result.err)
	}
}

// ────────────────────────────────────────────────────────────────────────
// The send transaction across processes.
// ────────────────────────────────────────────────────────────────────────

// The T-c window, with a real kill in it. The intent for a position is fsynced
// before the AEAD runs, so a process killed in between leaves a record that
// says "this position may have been used". The next process abandons it. The
// hole that leaves is ordinary; handing the number out twice is the failure
// this whole design exists to prevent.
func TestChatStateSendAbandonsAnUnfinishedPositionAfterAKill(t *testing.T) {
	env := newProcessEnv(t)
	env.seedGroupState(t)
	checkpoint := filepath.Join(env.tempDir, "pending-generation")

	victim, victimDone := env.start(t, "tc-crash-mid-send", "tc-crash-ready",
		helperCheckpnt+"="+checkpoint, helperClientID+"="+testClientA)
	env.waitReady(t, "tc-crash-ready")
	env.waitReady(t, "pending-generation")

	raw, err := os.ReadFile(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	killed, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	// The intent has to be on the disk already, before anything was encrypted.
	stranded := env.readRecord(t)
	if stranded.PendingSend == nil || stranded.PendingSend.Generation != killed {
		t.Fatalf("the intent was not durable at the AEAD: %+v", stranded.PendingSend)
	}
	if len(stranded.Outbox) != 0 {
		t.Fatalf("a ciphertext existed before the AEAD: %+v", stranded.Outbox)
	}

	if err := victim.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if result := waitForChild(t, victim, victimDone); result.err == nil {
		t.Fatalf("the killed child exited cleanly: %q", result.output)
	}

	next, nextDone := env.start(t, "tc-send", "tc-next-ready",
		helperClientID+"=55555555-5555-4555-8555-555555555555")
	env.waitReady(t, "tc-next-ready")
	generation, _, ciphertext := parseTcSent(t, waitForChild(t, next, nextDone))
	if generation <= killed {
		t.Fatalf("generation %d was handed out again after the kill (killed at %d)",
			generation, killed)
	}
	if at := positionOf(t, mustDecode(t, ciphertext)); at.Generation == killed {
		t.Fatalf("the ciphertext was built at the abandoned position %d", killed)
	}

	rec := env.readRecord(t)
	if rec.PendingSend != nil {
		t.Fatalf("the intent survived the recovery: %+v", rec.PendingSend)
	}
	if rec.positionTaken(Position{ContentType: ContentTypeApplication, Generation: killed}) {
		t.Fatalf("the abandoned position %d carries an outbox entry", killed)
	}
}

// Two processes sending at once, with the window between reading the position
// and using it held open on purpose. Whether they collide is judged on the
// positions taken out of the ciphertexts, not on what either process reported:
// the reservation numbers can differ while the bytes land on the same key.
func TestChatStateSendDoesNotLetTwoProcessesShareAPosition(t *testing.T) {
	env := newProcessEnv(t)
	env.seedGroupState(t)

	firstCmd, firstDone := env.start(t, "tc-send", "tc-first-ready",
		helperClientID+"=55555555-5555-4555-8555-555555555555",
		helperDelayMs+"=250")
	secondCmd, secondDone := env.start(t, "tc-send", "tc-second-ready",
		helperClientID+"=66666666-6666-4666-8666-666666666666",
		helperDelayMs+"=250")
	env.waitReady(t, "tc-first-ready")
	env.waitReady(t, "tc-second-ready")

	_, _, firstCipher := parseTcSent(t, waitForChild(t, firstCmd, firstDone))
	_, _, secondCipher := parseTcSent(t, waitForChild(t, secondCmd, secondDone))
	if firstCipher == secondCipher {
		t.Fatalf("both processes produced the same ciphertext: %q", firstCipher)
	}

	firstAt := positionOf(t, mustDecode(t, firstCipher))
	secondAt := positionOf(t, mustDecode(t, secondCipher))
	if firstAt == secondAt {
		t.Fatalf("both ciphertexts were built at %+v", firstAt)
	}

	rec := env.readRecord(t)
	if len(rec.Outbox) != 2 {
		t.Fatalf("the record holds %d outbox entries, want 2", len(rec.Outbox))
	}
	if rec.Outbox[0].Position == rec.Outbox[1].Position {
		t.Fatalf("one writer overwrote the other: %+v", rec.Outbox)
	}
	if string(rec.GroupState) != string(fakeState(0, 0, 2)) {
		t.Fatalf("the chain ended at %q; one advance was lost", rec.GroupState)
	}
}

// The receive side's boundary is atomicity rather than ordering: the advanced
// state, the delivery mark and the sealed copy are one replacement. A kill
// after the decrypt and before that write leaves none of the three, and a
// completed one leaves all three. There is no arrangement that leaves a mark
// without a copy.
func TestChatStateReceiveConfirmsTheMarkAndTheCopyTogetherAcrossAKill(t *testing.T) {
	env := newProcessEnv(t)
	env.seedGroupState(t)
	checkpoint := filepath.Join(env.tempDir, "opened")

	victim, victimDone := env.start(t, "tc-crash-mid-receive", "tc-rx-crash-ready",
		helperCheckpnt+"="+checkpoint, helperCount+"=1")
	env.waitReady(t, "tc-rx-crash-ready")
	env.waitReady(t, "opened")
	if err := victim.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if result := waitForChild(t, victim, victimDone); result.err == nil {
		t.Fatalf("the killed child exited cleanly: %q", result.output)
	}

	rec := env.readRecord(t)
	if len(rec.Received) != 0 || len(rec.History) != 0 {
		t.Fatalf("a killed delivery left mark=%d copy=%d behind",
			len(rec.Received), len(rec.History))
	}
	if string(rec.GroupState) != string(fakeState(0, 0, 0)) {
		t.Fatalf("a killed delivery advanced the stored state: %q", rec.GroupState)
	}

	next, nextDone := env.start(t, "tc-receive", "tc-rx-ready", helperCount+"=1")
	env.waitReady(t, "tc-rx-ready")
	if out := waitForChild(t, next, nextDone); !strings.Contains(out.output, "tc-received:true:false") {
		t.Fatalf("the retry did not deliver: %q", out.output)
	}

	confirmed := env.readRecord(t)
	if len(confirmed.Received) != 1 || len(confirmed.History) != 1 {
		t.Fatalf("the delivery landed as mark=%d copy=%d; want one of each",
			len(confirmed.Received), len(confirmed.History))
	}
	if confirmed.Generation != rec.Generation+1 {
		t.Fatalf("the delivery took %d writes; the mark and the copy are not one replacement",
			confirmed.Generation-rec.Generation)
	}

	// A re-read in yet another process comes out of the sealed copy.
	reread, rereadDone := env.start(t, "tc-receive", "tc-rx-again-ready", helperCount+"=1")
	env.waitReady(t, "tc-rx-again-ready")
	if out := waitForChild(t, reread, rereadDone); !strings.Contains(out.output, "tc-received:false:true") {
		t.Fatalf("the re-read did not come from history: %q", out.output)
	}
}

// A retransmission from another process sends the bytes the first one stored.
func TestChatStateSendRetransmitReusesTheStoredCiphertext(t *testing.T) {
	env := newProcessEnv(t)
	env.seedGroupState(t)

	sender, senderDone := env.start(t, "tc-send", "tc-send-ready",
		helperClientID+"="+testClientA)
	env.waitReady(t, "tc-send-ready")
	sentAt, created, sentBytes := parseTcSent(t, waitForChild(t, sender, senderDone))
	if !created {
		t.Fatal("the first send did not create an outbox entry")
	}

	resender, resenderDone := env.start(t, "tc-send", "tc-resend-ready",
		helperClientID+"="+testClientA)
	env.waitReady(t, "tc-resend-ready")
	resentAt, recreated, resentBytes := parseTcSent(t, waitForChild(t, resender, resenderDone))
	if recreated {
		t.Fatal("the retransmission encrypted again")
	}
	if sentAt != resentAt || sentBytes != resentBytes {
		t.Fatalf("retransmission differs: %d/%s vs %d/%s",
			sentAt, sentBytes, resentAt, resentBytes)
	}
	if got := env.readRecord(t).GroupState; string(got) != string(fakeState(0, 0, 1)) {
		t.Fatalf("the retransmission moved the chain: %q", got)
	}
}

// A Commit built and posted by a process that died before it heard the
// verdict. The next process must find it, must not guess which way it went,
// and must refuse everything that would build on the undecided epoch. The
// confirmed state has to be exactly where the dead process left it, including
// the anchor: an anchor that had taken the pending epoch would read the record
// as rewound here and latch the conversation (§7.3.3).
func TestChatStatePendingCommitSurvivesAKillAndBlocksUntilSettled(t *testing.T) {
	env := newProcessEnv(t)
	env.seedGroupState(t)
	checkpoint := filepath.Join(env.tempDir, "commit-pending")

	victim, victimDone := env.start(t, "commit-crash", "commit-crash-ready",
		helperCheckpnt+"="+checkpoint, helperClientID+"="+testCommitA)
	env.waitReady(t, "commit-crash-ready")
	env.waitReady(t, "commit-pending")

	stranded := env.readRecord(t)
	if stranded.Pending == nil || stranded.Pending.ClientCommitID != testCommitA {
		t.Fatalf("the commit was not durable as pending: %+v", stranded.Pending)
	}
	if stranded.Epoch != 0 {
		t.Fatalf("building a commit advanced the confirmed epoch to %d", stranded.Epoch)
	}
	if want := string(fakePendingState(0, 0, 0, 1)); string(stranded.GroupState) != want {
		t.Fatalf("group state = %q, want %q", stranded.GroupState, want)
	}
	if anchor := env.readAnchor(t); anchor.Epoch != 0 || anchor.NeedsRekey {
		t.Fatalf("the anchor took the pending epoch or latched: %+v", anchor)
	}

	if err := victim.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if result := waitForChild(t, victim, victimDone); result.err == nil {
		t.Fatalf("the killed child exited cleanly: %q", result.output)
	}

	gates, gatesDone := env.start(t, "commit-gates", "commit-gates-ready")
	env.waitReady(t, "commit-gates-ready")
	want := "commit-gates:true:true:true:true:" + testCommitA
	if out := waitForChild(t, gates, gatesDone); !strings.Contains(out.output, want) {
		t.Fatalf("after the kill the gates reported %q, want %q", out.output, want)
	}

	confirm, confirmDone := env.start(t, "commit-confirm", "commit-confirm-ready",
		helperClientID+"="+testCommitA)
	env.waitReady(t, "commit-confirm-ready")
	if out := waitForChild(t, confirm, confirmDone); !strings.Contains(out.output, "commit-confirmed:1:true") {
		t.Fatalf("the verdict did not settle the commit: %q", out.output)
	}

	settled := env.readRecord(t)
	if settled.Pending != nil {
		t.Fatalf("the pending outlived its verdict: %+v", settled.Pending)
	}
	if settled.Epoch != 1 || string(settled.GroupState) != string(fakeState(1, 0, 0)) {
		t.Fatalf("record after the verdict: epoch %d state %q", settled.Epoch, settled.GroupState)
	}
	if anchor := env.readAnchor(t); anchor.Epoch != 1 || anchor.NeedsRekey {
		t.Fatalf("anchor after the verdict: %+v", anchor)
	}

	next, nextDone := env.start(t, "tc-send", "commit-after-ready",
		helperClientID+"=55555555-5555-4555-8555-555555555555")
	env.waitReady(t, "commit-after-ready")
	if _, created, _ := parseTcSent(t, waitForChild(t, next, nextDone)); !created {
		t.Fatal("sending stayed blocked after the commit was settled")
	}
}

// ────────────────────────────────────────────────────────────────────────
// Harness.
// ────────────────────────────────────────────────────────────────────────

type processEnv struct {
	tempDir     string
	keyringPath string
	sealKey     []byte
}

// newProcessEnv gives every test its own HOME (and XDG_CONFIG_HOME / APPDATA)
// plus its own mock-keyring file. The state root is derived from
// os.UserConfigDir rather than an explicit override so the derivation itself is
// under test, and so a mistake in it cannot reach the developer's real state.
func newProcessEnv(t *testing.T) *processEnv {
	t.Helper()
	tempDir := t.TempDir()
	env := &processEnv{
		tempDir:     tempDir,
		keyringPath: filepath.Join(tempDir, "keyring.json"),
		sealKey:     make([]byte, sealKeyBytes),
	}

	// Pre-mint the seal key so every child derives the same conversation tag
	// without racing to create it.
	if _, err := rand.Read(env.sealKey); err != nil {
		t.Fatal(err)
	}
	seed := map[string]string{
		config.Service + "|" + sealKeyAccount(testOwner): base64.StdEncoding.EncodeToString(env.sealKey),
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.keyringPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", tempDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tempDir, "config"))
	t.Setenv("APPDATA", filepath.Join(tempDir, "appdata"))
	return env
}

func (e *processEnv) start(t *testing.T, mode, readyName string, extraEnv ...string) (*exec.Cmd, <-chan childResult) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChatStateProcessHelper$")
	cmd.Env = append(os.Environ(),
		helperModeEnv+"="+mode,
		helperReadyEnv+"="+filepath.Join(e.tempDir, readyName),
		helperKeyring+"="+e.keyringPath,
		"HOME="+e.tempDir,
		"XDG_CONFIG_HOME="+filepath.Join(e.tempDir, "config"),
		"APPDATA="+filepath.Join(e.tempDir, "appdata"),
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	done := make(chan childResult, 1)
	go func() {
		err := cmd.Wait()
		done <- childResult{output: output.String(), err: err}
	}()
	return cmd, done
}

func (e *processEnv) waitReady(t *testing.T, name string) {
	t.Helper()
	if err := waitForFile(filepath.Join(e.tempDir, name)); err != nil {
		t.Fatal(err)
	}
}

// parentStore lets the parent read what the children wrote. It is built from
// the seal key the harness minted rather than by looking one up, so a parent
// that cannot find the key fails the test instead of quietly minting a second
// one and reporting the children's records as missing.
func (e *processEnv) parentStore(t *testing.T) *Store {
	t.Helper()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	return &Store{
		secrets:     mirroredSecretStore{path: e.keyringPath},
		root:        root,
		owner:       testOwner,
		nameKey:     deriveSubkey(e.sealKey, nameSubkeyLabel),
		aeadKey:     deriveSubkey(e.sealKey, aeadSubkeyLabel),
		historyKey:  deriveSubkey(e.sealKey, historySubkeyLabel),
		lockTimeout: LockTimeout,
	}
}

// seedGroupState gives the conversation a group for the send transaction to
// load. The parent does it once so that two children starting together are
// not also racing to create it.
func (e *processEnv) seedGroupState(t *testing.T) {
	t.Helper()
	store := e.parentStore(t)
	defer store.Close()
	if _, err := store.SaveGroupState(testConvA, noWatermark, fakeState(0, 0, 0)); err != nil {
		t.Fatalf("seed group state: %v", err)
	}
}

func (e *processEnv) readAnchor(t *testing.T) Anchor {
	t.Helper()
	store := e.parentStore(t)
	defer store.Close()
	anchor, err := loadAnchor(store.secrets, store.conversationTag(testConvA))
	if err != nil {
		t.Fatalf("load anchor: %v", err)
	}
	return anchor
}

func (e *processEnv) readRecord(t *testing.T) *Record {
	t.Helper()
	store := e.parentStore(t)
	defer store.Close()
	rec, err := store.readRecord(store.paths(testConvA), testConvA)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if rec == nil {
		t.Fatal("no record was written")
	}
	return rec
}

// mirroredSecretStore is the keyring every process in these tests shares: one
// JSON map, replaced atomically so a SIGKILL cannot truncate it.
type mirroredSecretStore struct{ path string }

func (s mirroredSecretStore) entries() map[string]string {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]string{}
	}
	return m
}

func (s mirroredSecretStore) Get(service, account string) (string, error) {
	value, ok := s.entries()[service+"|"+account]
	if !ok {
		return "", keychain.ErrSecretNotFound
	}
	return value, nil
}

func (s mirroredSecretStore) Set(service, account, value string) error {
	entries := s.entries()
	entries[service+"|"+account] = value
	return s.replace(entries)
}

func (s mirroredSecretStore) Delete(service, account string) error {
	entries := s.entries()
	key := service + "|" + account
	if _, ok := entries[key]; !ok {
		return keychain.ErrSecretNotFound
	}
	delete(entries, key)
	return s.replace(entries)
}

func (s mirroredSecretStore) replace(entries map[string]string) error {
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return replaceFile(filepath.Dir(s.path), s.path, raw)
}

type reservedRange struct {
	first      uint64
	count      int
	generation uint64
}

func parseReserved(t *testing.T, result childResult) reservedRange {
	t.Helper()
	fields := parseToken(t, result, "reserved:", 3)
	first, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	generation, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return reservedRange{first: first, count: count, generation: generation}
}

func parseSent(t *testing.T, result childResult) (uint64, string) {
	t.Helper()
	fields := parseToken(t, result, "sent:", 3)
	index, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if fields[1] != "true" {
		t.Fatalf("the first send did not create an outbox entry: %q", result.output)
	}
	return index, fields[2]
}

func parseResent(t *testing.T, result childResult) (uint64, string) {
	t.Helper()
	fields := parseToken(t, result, "resent:", 2)
	index, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return index, fields[1]
}

func parseTcSent(t *testing.T, result childResult) (uint64, bool, string) {
	t.Helper()
	fields := parseToken(t, result, "tc-sent:", 3)
	generation, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return generation, fields[1] == "true", fields[2]
}

func mustDecode(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func parseToken(t *testing.T, result childResult, prefix string, want int) []string {
	t.Helper()
	for _, line := range strings.Split(result.output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.SplitN(strings.TrimPrefix(line, prefix), ":", want)
		if len(fields) != want {
			t.Fatalf("malformed %q line: %q", prefix, line)
		}
		return fields
	}
	t.Fatalf("no %q line in child output: %q (err=%v)", prefix, result.output, result.err)
	return nil
}

// waitForLoggedLines blocks until the progress file holds at least want whole
// lines and returns how many it found. A partial line left by a kill is not
// counted: it is not yet a claim that a position was handed out.
func waitForLoggedLines(t *testing.T, path string, want int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := countLogged(t, path); got >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hammer child logged %d reservations in 10s, want %d",
				countLogged(t, path), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func countLogged(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if _, err := strconv.ParseUint(line, 10, 64); err == nil {
			count++
		}
	}
	return count
}

func highestLogged(t *testing.T, path string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	highest := uint64(0)
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		value, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			// A line torn by the kill is not a claim about a position.
			continue
		}
		seen = true
		if value > highest {
			highest = value
		}
	}
	if !seen {
		t.Fatalf("the hammer child logged no reservations: %q", raw)
	}
	return highest
}

func tempFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			found = append(found, entry.Name())
		}
	}
	return found
}

func assertChildBlocked(t *testing.T, done <-chan childResult) {
	t.Helper()
	select {
	case result := <-done:
		t.Fatalf("a contender got past the conversation lock: output=%q err=%v",
			result.output, result.err)
	case <-time.After(200 * time.Millisecond):
	}
}

func waitForChild(t *testing.T, cmd *exec.Cmd, done <-chan childResult) childResult {
	t.Helper()
	select {
	case result := <-done:
		if strings.Contains(result.output, "error:") {
			t.Fatalf("child reported a failure: %q", result.output)
		}
		return result
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("timed out waiting for a chat state helper child")
		return childResult{}
	}
}

func waitForFile(path string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}
