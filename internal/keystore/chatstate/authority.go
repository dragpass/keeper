// authority.go — who may add and remove whom, and what this device keeps to
// notice a fork (design §0.3 policy 5, Q3 phase 1, Q4, Q16).
//
// # Removes
//
// A Remove of account A's leaf by committer C is accepted when one of these
// holds:
//
//	R1  A is C's own account.
//	R2  the same Commit adds a leaf of A (a replace, or a rejoin).
//	R3  a signed permit names A as having left the organization: this
//	    operation's pending_removal_account_ids, or an earlier one this record
//	    latched (RemovalLatch).
//	R3b the member set the server signed for this very Commit no longer holds
//	    A (the handshake row's attestation). Receiving only: it is how a room
//	    owner's or admin's Remove is told from a member's.
//	R4i a person on this device asked for it. Building only.
//
// # Adds
//
// A received Add is accepted on the leaf verification and the trust state of
// the account it brings in (§5.3), and nothing else: no permit, member set or
// role the server supplies is authority for it, because a server that could
// name an account could then have it added and read everything after. That
// leaves any member free to Add any account whose leaf verifies. 임시, 정책
// 미충족 (Q3): inbound Add authority against a malicious server waits for room
// roles in the authenticated group context (Q3 phase 2, wave 5).
//
// An Add this device builds needs R4i, a rejoin (R2 with the account's own
// signed request, and a leaf of the account already in the authenticated
// tree), or a replace the permit lists. A group's first Commit is its create,
// judged by nobody but its builder.
//
// Only Add and Remove are allowed at all. Any other proposal type is refused.
//
// 임시, 정책 미충족 (Q5): server-attested. R3 and R3b rest on the server's
// signature, which policy 5 says must not be enough on its own; R4i rests on
// the app's word. They stand in for what the Keeper cannot yet check itself.
// TODO(Q5): replace R3 with an org-admin-signed removal statement.
// TODO(Q3 phase 2): replace R3b, R4i and inbound Add authority with roles held
// in GroupContext.
//
// What a client cannot know on its own, stated here so it is not hidden: a
// server that omits a departed account from every permit keeps that account in
// the group, and a server that signs a false member set can make a Remove look
// authorized. These rules stop a member with a modified client from removing
// others; they do not stop the server.
//
// # A refusal
//
// A Commit refused on receipt is not applied, and the conversation latches
// read-only with cause unauthorized_commit, naming the epoch and the
// committer (Q4). The members that applied it are on an epoch this device
// will never reach, so it is a fork seen from here; nothing is reset and no
// new group is made.

package chatstate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
)

// ErrCommitUnauthorized — a Commit carries an Add or a Remove, or a proposal
// type, that the authority rules above do not allow. Built locally it is
// refused and nothing is built; received, it latches the conversation.
var ErrCommitUnauthorized = errors.New("chat state refused a commit its committer is not authorized to make")

// UnauthorizedCommitError is ErrCommitUnauthorized with the committer the
// group's own tree names and the rule that failed, as a condition and never a
// value.
type UnauthorizedCommitError struct {
	CommitterAccountID string
	CommitterDeviceID  string
	Reason             string
}

func (e *UnauthorizedCommitError) Error() string {
	return ErrCommitUnauthorized.Error() + ": " + e.Reason
}

func (e *UnauthorizedCommitError) Unwrap() error { return ErrCommitUnauthorized }

// CommitAuthority is the evidence a received Commit is judged by.
type CommitAuthority struct {
	// PendingRemovals is R3: the permit's list and this record's latch.
	PendingRemovals []string

	// CommitMembers is the member set the server signed for the Commit being
	// judged, and CommitMembersKnown whether the row carried such a signature.
	CommitMembers      []string
	CommitMembersKnown bool
}

// AuthorityReceiver is a cipher that judges the Commits it applies. The
// store hands it the evidence before every Open and ApplyMessage; a cipher
// that does not implement it judges nothing, which only test fakes do.
type AuthorityReceiver interface {
	SetCommitAuthority(CommitAuthority)
}

// ServerCommitMembers is a member set the server signed for one Commit,
// already verified by the caller. Nil means the row carried none.
type ServerCommitMembers struct {
	AccountIDs []string
}

func (s *Store) armAuthority(cipher any, rec *Record, wm ServerWatermark, members *ServerCommitMembers) {
	receiver, ok := cipher.(AuthorityReceiver)
	if !ok {
		return
	}
	auth := CommitAuthority{
		PendingRemovals: mergedAccounts(wm.PendingRemovals, rec.RemovalLatch),
	}
	if members != nil {
		auth.CommitMembers = slices.Clone(members.AccountIDs)
		auth.CommitMembersKnown = true
	}
	receiver.SetCommitAuthority(auth)
}

func mergedAccounts(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, id := range l {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// CommitChange is what one received Commit does, in accounts: who committed
// it (from the group's own tree, before the Commit), one entry per removed
// leaf, one per added leaf, and how many proposals are neither.
type CommitChange struct {
	CommitterAccountID string
	CommitterDeviceID  string
	Removed            []string
	Added              []string
	OtherProposals     int
}

// JudgeReceived holds a received Commit to the rules above. Nil means apply
// it; otherwise an *UnauthorizedCommitError naming the committer.
func JudgeReceived(change CommitChange, auth CommitAuthority) error {
	refuse := func(reason string) error {
		return &UnauthorizedCommitError{
			CommitterAccountID: change.CommitterAccountID,
			CommitterDeviceID:  change.CommitterDeviceID,
			Reason:             reason,
		}
	}
	if change.OtherProposals > 0 {
		return refuse("the commit carries a proposal other than add and remove")
	}
	for _, account := range change.Removed {
		member, known := slices.Contains(auth.CommitMembers, account), auth.CommitMembersKnown
		switch {
		case account == change.CommitterAccountID: // R1
		case slices.Contains(change.Added, account): // R2
		case slices.Contains(auth.PendingRemovals, account): // R3
		case known && !member: // R3b
		default:
			return refuse("a remove is not the committer's own, not paired with an add, and not a signed departure")
		}
	}
	return nil
}

// requireAuthorizedPlan holds a locally built plan to the rules above, before
// anything is built. A create is not judged here: it is the group's first
// Commit (CreateGroup never calls this). A replace is held to the permit's list
// (requireListedReplacements), and a rejoin to its signed request by the
// caller and to the authenticated tree by the cipher.
func requireAuthorizedPlan(plan CommitPlan, rec *Record, wm ServerWatermark) error {
	if len(plan.AddKeyPackages) > 0 && !plan.UserInitiated {
		return &UnauthorizedCommitError{Reason: "an add outside a create needs a person on this device to ask for it"}
	}
	pending := mergedAccounts(wm.PendingRemovals, rec.RemovalLatch)
	for _, account := range plan.RemoveAccountIDs {
		if !plan.UserInitiated && !slices.Contains(pending, account) {
			return &UnauthorizedCommitError{Reason: "a remove names an account no permit lists as departed and nobody here asked for"}
		}
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────
// The fork ring (Q16).
// ────────────────────────────────────────────────────────────────────────

// ConfirmedCommitCapacity bounds the fork ring. A catch-up compares a row for
// an epoch this device already confirmed against it; an epoch older than the
// ring cannot be compared, which is stated rather than hidden.
const ConfirmedCommitCapacity = 64

// ConfirmedCommit is one confirmed epoch and the Commit that produced it.
// The epoch_authenticator mls-rs exposes would name the epoch too, but a log
// row cannot be compared against it without applying the Commit, and this
// device is already past that epoch: the Commit's own bytes are what a row
// can be held to.
type ConfirmedCommit struct {
	Epoch      uint64 `json:"epoch"`
	CommitHash string `json:"commit_sha256"`
}

func commitHash(commit []byte) string {
	sum := sha256.Sum256(commit)
	return hex.EncodeToString(sum[:])
}

// noteConfirmed records that the Commit commit produced epoch.
func (r *Record) noteConfirmed(epoch uint64, commit []byte) {
	r.ConfirmedCommits = slices.DeleteFunc(r.ConfirmedCommits, func(c ConfirmedCommit) bool {
		return c.Epoch == epoch
	})
	r.ConfirmedCommits = append(r.ConfirmedCommits, ConfirmedCommit{Epoch: epoch, CommitHash: commitHash(commit)})
	if len(r.ConfirmedCommits) > ConfirmedCommitCapacity {
		r.ConfirmedCommits = slices.Clone(r.ConfirmedCommits[len(r.ConfirmedCommits)-ConfirmedCommitCapacity:])
	}
}

// forkAt reports whether commit, served as the Commit that produced an epoch
// this device already confirmed, is another one than this device applied
// there. False when the ring does not hold that epoch: nothing to compare.
func (r *Record) forkAt(epoch uint64, commit []byte) bool {
	for _, c := range r.ConfirmedCommits {
		if c.Epoch == epoch {
			return c.CommitHash != commitHash(commit)
		}
	}
	return false
}
