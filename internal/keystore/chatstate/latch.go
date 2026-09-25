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
// lost or stolen. So this latch is S-1 with a different exit: the same rules,
// judged in the same four operations, with "every confirmed leaf of the
// account signs with the expected key" counting as "the leaf is gone".
//
// It is keyed by account and holds one expected fingerprint each. A permit
// entry for an account already latched updates the expected fingerprint and
// lifts nothing, so a takeover that is itself taken over (Bob → Bob2 → Bob3
// before the first replace lands) waits for Bob3's key rather than for a key
// that will never arrive. Permits still only add: they can change which key
// must appear, and only the confirmed roster lifts.
//
// Why a server that rewrites the fingerprint gains nothing: lifting needs every
// confirmed leaf of the account on the expected key, and a leaf only enters the
// confirmed tree through a Commit whose new leaf passed §5.3 — an account-key
// signed declaration for exactly that key. The server cannot mint one. The one
// key it could name without one is a key already in the tree: the old leaf
// being replaced. So every fingerprint the latch has seen being replaced is
// kept in Superseded, and a latch expecting one of those never lifts on it.
// Without that, rewriting the entry to the old device's own key would lift the
// latch with no replace at all.
//
// What this does not do, stated in §6.4.1's words: a server that omits the
// entry is not detected here.
// ────────────────────────────────────────────────────────────────────────

// ErrLeafReplacementPending — this device's confirmed group still holds a
// leaf of an account a permit named as taken over by a new device, under a
// key other than the new device's. Commits and receiving are not refused: a
// replace Commit is the way out.
var ErrLeafReplacementPending = errors.New("chat state is waiting for a leaf replacement commit before it may encrypt")

// LeafReplacement is one account a new device took over and the signature
// key fingerprint of that device's leaf, as a permit states it.
type LeafReplacement struct {
	AccountID      string `json:"account_id"`
	NewFingerprint string `json:"new_signature_key_fp"`
}

// ReplacementLatch is one latched account: the key that must replace its
// leaves, and every key of it the confirmed roster held that was not that one
// while latched. Superseded is sorted.
type ReplacementLatch struct {
	AccountID      string   `json:"account_id"`
	NewFingerprint string   `json:"new_signature_key_fp"`
	Superseded     []string `json:"superseded_fps,omitempty"`
}

func (r ReplacementLatch) equal(o ReplacementLatch) bool {
	return r.AccountID == o.AccountID && r.NewFingerprint == o.NewFingerprint &&
		slices.Equal(r.Superseded, o.Superseded)
}

// RosterLeaf is one leaf of the confirmed tree: whose it is, which device of
// that account its credential names, and which key it signs with, as the
// lowercase hex SHA-256 fingerprint of that key.
type RosterLeaf struct {
	AccountID   string
	DeviceID    string
	Fingerprint string
}

// judgeReplacements is judgeRemovals for the leaf-replacement latch: the
// stored latch with the permit's entries merged in by account (the permit's
// fingerprint wins), kept where a confirmed leaf of the account signs with
// another key, or where the only key left is one the latch saw being
// replaced. Sorted by account.
func judgeReplacements(latched []ReplacementLatch, named []LeafReplacement, roster RosterReader) ([]ReplacementLatch, error) {
	if len(latched) == 0 && len(named) == 0 {
		return nil, nil
	}
	leaves, err := roster.ConfirmedLeaves()
	if err != nil {
		return nil, err
	}
	merged := make([]ReplacementLatch, 0, len(latched)+len(named))
	for _, l := range latched {
		merged = append(merged, ReplacementLatch{
			AccountID: l.AccountID, NewFingerprint: l.NewFingerprint, Superseded: slices.Clone(l.Superseded),
		})
	}
	for _, n := range named {
		i := slices.IndexFunc(merged, func(l ReplacementLatch) bool { return l.AccountID == n.AccountID })
		if i < 0 {
			merged = append(merged, ReplacementLatch{AccountID: n.AccountID, NewFingerprint: n.NewFingerprint})
			continue
		}
		merged[i].NewFingerprint = n.NewFingerprint
	}
	var out []ReplacementLatch
	for _, l := range merged {
		held, other := false, false
		for _, leaf := range leaves {
			if leaf.AccountID != l.AccountID {
				continue
			}
			held = true
			if leaf.Fingerprint != l.NewFingerprint {
				other = true
				if !slices.Contains(l.Superseded, leaf.Fingerprint) {
					l.Superseded = append(l.Superseded, leaf.Fingerprint)
				}
			}
		}
		if other || (held && slices.Contains(l.Superseded, l.NewFingerprint)) {
			slices.Sort(l.Superseded)
			out = append(out, l)
		}
	}
	slices.SortFunc(out, func(a, b ReplacementLatch) int { return strings.Compare(a.AccountID, b.AccountID) })
	return out, nil
}

// ────────────────────────────────────────────────────────────────────────
// The device revocation latch (design Q13).
//
// An account that revokes one of its devices signs a revocation of that
// device's leaf, and the remaining members remove the leaf on its strength.
// Until that has happened here, the revoked device still holds the current
// epoch's keys, and it may be the one that was lost or stolen. So this is S-1
// once more, keyed by (account, device): the permit names the revocation, it
// only ever adds, and only a confirmed tree without that device's leaf lifts
// it. The permit is the server's word and is only a reason to stop
// encrypting; the Remove itself rests on the account's signature, never on
// this list.
//
// What this does not do, stated in §6.4.1's words: a server that omits the
// entry is not detected here.
// ────────────────────────────────────────────────────────────────────────

// ErrDeviceRevocationPending — this device's confirmed group still holds the
// leaf of a device its account revoked. Commits and receiving are not
// refused: a Remove of that leaf is the way out.
var ErrDeviceRevocationPending = errors.New("chat state is waiting for a revoked device's leaf to be removed before it may encrypt")

// judgeDeviceRevocations is judgeRemovals for the device revocation latch,
// keyed by (account, device). Sorted.
func judgeDeviceRevocations(latched, named []DeviceRef, roster RosterReader) ([]DeviceRef, error) {
	if len(latched) == 0 && len(named) == 0 {
		return nil, nil
	}
	leaves, err := roster.ConfirmedLeaves()
	if err != nil {
		return nil, err
	}
	var out []DeviceRef
	for _, ref := range append(slices.Clone(latched), named...) {
		held := slices.ContainsFunc(leaves, func(l RosterLeaf) bool {
			return l.AccountID == ref.AccountID && l.DeviceID == ref.DeviceID
		})
		if held && !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	sortDeviceRefs(out)
	return out, nil
}

func sortDeviceRefs(refs []DeviceRef) {
	slices.SortFunc(refs, func(a, b DeviceRef) int {
		if c := strings.Compare(a.AccountID, b.AccountID); c != 0 {
			return c
		}
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
}

// latches is every latch after one operation.
type latches struct {
	removals     []string
	replacements []ReplacementLatch
	devices      []DeviceRef
}

func (l latches) held() bool {
	return len(l.removals) > 0 || len(l.replacements) > 0 || len(l.devices) > 0
}

// judgeLatches runs every judgement against one permit and one roster.
func judgeLatches(rec *Record, wm ServerWatermark, roster RosterReader) (latches, error) {
	removals, err := judgeRemovals(rec.RemovalLatch, wm.PendingRemovals, roster)
	if err != nil {
		return latches{}, err
	}
	replacements, err := judgeReplacements(rec.LeafReplacementLatch, wm.PendingLeafReplacements, roster)
	if err != nil {
		return latches{}, err
	}
	devices, err := judgeDeviceRevocations(rec.DeviceRevokeLatch, wm.PendingDeviceRevocations, roster)
	if err != nil {
		return latches{}, err
	}
	return latches{removals: removals, replacements: replacements, devices: devices}, nil
}

// storedLatches is what the record already holds, for an operation that
// removed this device and so has no roster left to judge against.
func storedLatches(rec *Record) latches {
	return latches{removals: rec.RemovalLatch, replacements: rec.LeafReplacementLatch, devices: rec.DeviceRevokeLatch}
}

func (l latches) apply(rec *Record) {
	rec.RemovalLatch = l.removals
	rec.LeafReplacementLatch = l.replacements
	rec.DeviceRevokeLatch = l.devices
}

func (l latches) sameAs(rec *Record) bool {
	return slices.Equal(l.removals, rec.RemovalLatch) &&
		slices.EqualFunc(l.replacements, rec.LeafReplacementLatch, ReplacementLatch.equal) &&
		slices.Equal(l.devices, rec.DeviceRevokeLatch)
}

// expected is the latch as the app sees it: which key each account waits for.
func (l latches) expected() []LeafReplacement {
	out := make([]LeafReplacement, len(l.replacements))
	for i, r := range l.replacements {
		out[i] = LeafReplacement{AccountID: r.AccountID, NewFingerprint: r.NewFingerprint}
	}
	return out
}
