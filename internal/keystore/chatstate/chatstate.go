// Package chatstate holds one sealed file per conversation for DragPass chat
// v2's cipher state (the MLS group state and its send / receive counters).
//
// It exists because `keychain.SecretStore` cannot hold this. Its whole
// interface is Get / Set / Delete, so there is no primitive that changes the
// state body and its rollback anchor together; a Windows Credential Manager
// entry caps around 2.5 KB, which an MLS group state passes at realistic sizes;
// and it cannot enumerate, which logout-time erasure needs. Papering over the
// three with chunking, journals, and index entries would put the key-reuse
// defect in the paper. The trade is written down: the bulk moves from OS
// keyring protection to file permissions plus a seal key, and the seal key
// stays in the keyring so the files alone open nothing. Rationale and the
// alternatives that were rejected: dragpass-control-plane
// docs/security/adr-ratchet-state-storage.md S3-S7.
//
// Four properties this package owes the layer above, none of which MLS can
// restore once broken:
//
//   - One conversation is written by one process at a time (an advisory file
//     lock per conversation, never a global one).
//   - A state change is one whole-file replacement: temp file, fsync, rename,
//     directory fsync. A crash leaves the old file or the new one.
//   - A rewound state is refused, not continued. A monotonic generation in the
//     keyring catches a file restored on its own; a server watermark carried
//     inside the signed permit catches a file and an anchor restored together.
//   - A chain position is consumed before the caller encrypts with it, and the
//     ciphertext built from it is stored so a retransmission is the same bytes.
//
// What this package deliberately does not do: it never hands the group state
// across IPC in either direction. Record.GroupState is opaque bytes that only
// in-process Keeper code touches, which is why no action in the protocol reads
// or writes it. MLS integration is the next step; this is the place it will
// keep its state.
package chatstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Sentinel failures the handler layer maps onto protocol error codes.
var (
	// ErrRekeyRequired — the stored state is behind what this device has
	// already committed, or behind what the server has already accepted. The
	// conversation is locked for sending until a new epoch is established.
	// There is deliberately no "continue anyway" path: a rewound chain reuses
	// (key, nonce) pairs, and that is the one failure in this design that
	// cannot be taken back.
	ErrRekeyRequired = errors.New("chat state requires a new epoch")

	// ErrConflict — the file changed between the read and the write inside one
	// locked section. The lock should make this impossible, which is exactly
	// why it is checked: a lock that silently stopped working must surface as a
	// failure rather than as an overwrite.
	ErrConflict = errors.New("chat state changed under the lock")

	// ErrLockTimeout — another process held the conversation lock for longer
	// than the ceiling. Distinct from every other failure so the caller never
	// has to guess whether proceeding without the lock is an option.
	ErrLockTimeout = errors.New("chat state lock timeout")

	// ErrNotFound — no outbox entry for the requested client message id.
	ErrNotFound = errors.New("chat state entry not found")

	// ErrPositionTaken — the chain position already carries a different
	// message. Refusing is the point: two plaintexts at one position is the
	// key-reuse failure this package is built to prevent.
	ErrPositionTaken = errors.New("chain position already carries a message")

	// ErrPositionNotReserved — the position sits at or beyond the sending
	// chain's high-water mark, so nothing ever handed it out. Reserve raises
	// that mark and so does Send, which is why this is phrased as the mark
	// rather than as one of the two paths.
	ErrPositionNotReserved = errors.New("chain position was not reserved")
)

const (
	// RootEnvVar overrides the state root. KEEPER_E2E_MODE swaps the keyring
	// for a mock and leaves the filesystem alone, so the file side needs an
	// isolation switch of the same rank or an e2e run writes into the
	// developer's real state.
	RootEnvVar = "KEEPER_CHAT_STATE_DIR"

	dirName      = "chat-state"
	recordSuffix = ".state"
	lockSuffix   = ".lock"
	tempPrefix   = "tmp-"
)

// Root resolves the state root. Derived from os.UserConfigDir rather than
// hard-coded so the HOME / XDG_CONFIG_HOME / APPDATA overrides the process
// tests already set keep the tests off the developer's own state.
func Root() (string, error) {
	if override := os.Getenv(RootEnvVar); override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve chat state root: %w", err)
	}
	return filepath.Join(dir, "dragpass-keeper", dirName), nil
}
