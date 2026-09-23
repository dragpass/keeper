// latch.go — the Keeper half of S-1, design §6.4.1.
//
// Once a permit names an account as removed from the organization, this device
// refuses to encrypt new application messages in that conversation until its
// own confirmed group state no longer holds a leaf for that account. Three
// rules, and the reason each is shaped the way it is:
//
//   - A permit only ever adds. The list is the server's word, the server is
//     UNTRUSTED, and a later permit that stops naming an account is not
//     evidence that its leaf is gone (§6.4.1 condition 3).
//   - Only the confirmed roster takes an account out. A built Commit that
//     would remove the leaf is a fork until the server accepts it (§7.3.1),
//     and the epoch it would leave behind is the one the departed member holds
//     keys for, so a pending Commit unlatches nothing (condition 4).
//   - An account the confirmed roster does not hold is not latched at all:
//     there is no leaf of it to protect against.
//
// The judgement needs the roster, which lives inside the MLS state and only a
// loaded session can read. So it runs in the operations that load one — Send,
// Receive, BeginCommit and ConfirmCommit — and not in the ones that never do.
// Those encrypt no MLS message, and the next operation that could is judged
// against its own permit before it does.
//
// What this does not do, stated in §6.4.1's words: the trigger is the client
// knowing about the removal, and today only the server tells it. A server that
// omits the list is not detected here.

package chatstate

import (
	"errors"
	"slices"
)

// ErrRotationPending — this device's confirmed group still holds a leaf of an
// account a permit named as removed, so a new application message would be
// encrypted under keys that account can derive. Commits and receiving are not
// refused: a Remove Commit is the only way out.
var ErrRotationPending = errors.New("chat state is waiting for a remove commit before it may encrypt")

// RosterReader reports who the confirmed group state holds.
type RosterReader interface {
	// ConfirmedAccounts returns the account of every leaf in the confirmed
	// tree, never one a pending Commit would add or keep out. An identity
	// that does not parse as a DragPass device identity is an error rather
	// than a skipped leaf: skipping it could leave an account unlatched.
	ConfirmedAccounts() ([]string, error)
}

// judgeRemovals returns the latch after one operation: what was latched plus
// what the permit named, kept only where the confirmed roster still holds the
// account. The roster is read only when there is something to judge, so a
// conversation nobody was removed from never pays for it.
func judgeRemovals(latched, named []string, roster RosterReader) ([]string, error) {
	if len(latched) == 0 && len(named) == 0 {
		return nil, nil
	}
	members, err := roster.ConfirmedAccounts()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, account := range append(slices.Clone(latched), named...) {
		if slices.Contains(members, account) && !slices.Contains(out, account) {
			out = append(out, account)
		}
	}
	slices.Sort(out)
	return out, nil
}
