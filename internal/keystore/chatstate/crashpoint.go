// crashpoint.go — named points inside a transaction where a kill harness can
// stop a real Keeper process.
//
// A SIGKILL sent from outside cannot be timed to land between two fsyncs of
// one call, so the harness asks the process to stop itself at a named point
// and kills it there: internal/keystore/killharness. Without the
// keeper_killseam build tag crashAt does nothing, no environment variable is
// read, and no release build carries the tag.

package chatstate

// Crash points, in the order a transaction reaches them.
const (
	// CrashSendAfterSeal — the AEAD ran, write 2 has not: a ciphertext exists
	// only in memory while write 1's intent is on disk.
	CrashSendAfterSeal = "send.after-seal"

	// CrashSendAfterWrite — write 2 is on disk and the answer has not left:
	// the app never learns the ciphertext it has to post.
	CrashSendAfterWrite = "send.after-write2"

	// CrashReceiveBatchAfterOpen — a display batch was opened, nothing of it
	// written.
	CrashReceiveBatchAfterOpen = "receive-batch.after-open"

	// CrashProcessAfterApply — somebody else's Commit is applied in memory,
	// nothing of it written.
	CrashProcessAfterApply = "process.after-apply"

	// CrashConfirmAfterApply — this device's own pending Commit is promoted
	// in memory, nothing of it written.
	CrashConfirmAfterApply = "confirm.after-apply"

	// CrashCommitAfterFile — a record is on disk and its anchor is not.
	CrashCommitAfterFile = "commit.after-file"
)

var crashAt = func(point string) {}
