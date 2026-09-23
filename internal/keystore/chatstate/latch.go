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
	"strings"
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

	// ConfirmedLeaves returns every leaf of the confirmed tree with the
	// fingerprint of the key it signs with, under the same rules as
	// ConfirmedAccounts: never a pending Commit's leaf, and an identity or a
	// key that does not parse is an error rather than a skipped leaf.
	ConfirmedLeaves() ([]RosterLeaf, error)
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

// ────────────────────────────────────────────────────────────────────────
// The leaf-replacement latch, design M4.4.
//
// A new device that takes over an account declares a new leaf, and the
// remaining members replace the account's old leaf with it. Until that has
// happened here, the old leaf is still in this device's confirmed group and
// holds the current epoch's keys, and the old device may be the one that was
// lost or stolen. So this latch is S-1 with a different exit: the same three
// rules, judged in the same four operations, with a leaf of the account whose
// key is the one the permit named counting as "the leaf is gone".
//
// It names a key and not only an account, so it cannot be satisfied by the
// wrong one. A latch for (account, fp) holds while any confirmed leaf of the
// account signs with another key, and lifts when every one of them signs with
// fp or none is left. The same statement as §6.4.1 applies: a server that
// omits the entry is not detected here.
// ────────────────────────────────────────────────────────────────────────

// ErrLeafReplacementPending — this device's confirmed group still holds a
// leaf of an account a permit named as taken over by a new device, under a
// key other than the new device's. Commits and receiving are not refused: a
// replace Commit is the way out.
var ErrLeafReplacementPending = errors.New("chat state is waiting for a leaf replacement commit before it may encrypt")

// LeafReplacement is one account a new device took over and the signature
// key fingerprint of that device's leaf.
type LeafReplacement struct {
	AccountID      string `json:"account_id"`
	NewFingerprint string `json:"new_signature_key_fp"`
}

// RosterLeaf is one leaf of the confirmed tree: whose it is and which key it
// signs with, as the lowercase hex SHA-256 fingerprint of that key.
type RosterLeaf struct {
	AccountID   string
	Fingerprint string
}

// judgeReplacements is judgeRemovals for the leaf-replacement latch: what was
// latched plus what the permit named, kept only where a confirmed leaf of the
// account signs with a key other than the named one. Sorted by account, then
// fingerprint, with no repeats.
func judgeReplacements(latched, named []LeafReplacement, roster RosterReader) ([]LeafReplacement, error) {
	if len(latched) == 0 && len(named) == 0 {
		return nil, nil
	}
	leaves, err := roster.ConfirmedLeaves()
	if err != nil {
		return nil, err
	}
	var out []LeafReplacement
	for _, r := range append(slices.Clone(latched), named...) {
		if slices.Contains(out, r) {
			continue
		}
		if slices.ContainsFunc(leaves, func(l RosterLeaf) bool {
			return l.AccountID == r.AccountID && l.Fingerprint != r.NewFingerprint
		}) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b LeafReplacement) int {
		if a.AccountID != b.AccountID {
			return strings.Compare(a.AccountID, b.AccountID)
		}
		return strings.Compare(a.NewFingerprint, b.NewFingerprint)
	})
	return out, nil
}

// latches is both latches after one operation.
type latches struct {
	removals     []string
	replacements []LeafReplacement
}

func (l latches) held() bool { return len(l.removals) > 0 || len(l.replacements) > 0 }

// judgeLatches runs both judgements against one permit and one roster.
func judgeLatches(rec *Record, wm ServerWatermark, roster RosterReader) (latches, error) {
	removals, err := judgeRemovals(rec.RemovalLatch, wm.PendingRemovals, roster)
	if err != nil {
		return latches{}, err
	}
	replacements, err := judgeReplacements(rec.LeafReplacementLatch, wm.PendingLeafReplacements, roster)
	if err != nil {
		return latches{}, err
	}
	return latches{removals: removals, replacements: replacements}, nil
}

// storedLatches is what the record already holds, for an operation that
// removed this device and so has no roster left to judge against.
func storedLatches(rec *Record) latches {
	return latches{removals: rec.RemovalLatch, replacements: rec.LeafReplacementLatch}
}

func (l latches) apply(rec *Record) {
	rec.RemovalLatch = l.removals
	rec.LeafReplacementLatch = l.replacements
}

func (l latches) sameAs(rec *Record) bool {
	return slices.Equal(l.removals, rec.RemovalLatch) &&
		slices.Equal(l.replacements, rec.LeafReplacementLatch)
}
