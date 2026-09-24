// authority.go — who may add and remove whom, and what this device keeps to
// notice a fork (design §0.3 policy 5, Q3, Q4, Q5 (b), Q13, Q16, Q27).
//
// # Where authority comes from
//
// Only from the authenticated group state and from signatures by accounts
// whose keys this device holds pinned. Nothing the server says or signs is
// authority for an Add or a Remove on its own (policy 5), with the one
// labelled exception below for groups made before 0.0.55.
//
//   - Room roles live in the group context (roles.go): an owner and admins.
//     The owner alone changes them; an owner or admin adds members; an owner
//     removes anybody and an admin anybody but the owner and the admins.
//   - A DM is marked as one in the group context and never adds anybody after
//     its create.
//   - Signed statements, carried inside the Commit's own authenticated data so
//     every receiver checks the same bytes, catch-up included:
//     an org admin's removal statement (Q5 (b)), the member's own signed leave
//     (Q13), and the account's own signed revoke of one device's leaf (Q13).
//     The leave and the revoke are verified with the account key in the
//     removed leaf's own declaration, which this device pinned when the leaf
//     entered. The admin statement is verified with the key it carries, held
//     to this device's pin for the admin account.
//
// # Removes
//
// A Remove of account A's leaf by committer C is accepted when one of these
// holds:
//
//	R1  A is C's own account (another leaf of it).
//	R2  the same Commit adds a leaf of A (a replace, or a rejoin).
//	S   a verified statement the Commit carries covers that leaf.
//	RR  C's role lets it remove A (roles.go roleMayRemove).
//	R3b legacy_temporary only: the member set the server signed for this very
//	    Commit no longer holds A. Receiving only.
//
// # Adds and roles
//
// roles.go: in a room an Add needs the committer to be owner or admin, in a
// DM there is none after the create, and a group without roles (legacy) takes
// any Add whose leaf verifies. In every group an account holds one leaf (Q14),
// judged on the tree after the Commit: an Add that leaves the account it adds
// with two leaves is refused, whether the other one was already in the tree
// or comes in with the same Commit. Only Add, Remove and a roles-only group
// context change are allowed at all.
//
// # Building
//
// A Commit this device builds is judged by the same rules before anything is
// built, over the change the plan would make (PlanJudge). On top of them,
// user_initiated gates the app's intent and nothing else: a local Add, a
// role-based Remove and an owner's roles change need a person to have asked;
// a Remove resting on a signed statement, a migration and an ownerless claim
// do not. It is never authority on its own.
//
// # What the client cannot know on its own, stated so it is not hidden
//
//   - Whether someone left the organization. A server that serves no removal
//     statement keeps that account in the group; this device cannot tell.
//   - Who the org admins are. The admin set is server-attested: a statement
//     verifies against the key of the account it names as admin, and this
//     device takes that account's first key on trust (TOFU) when it has no
//     pin for it. A server that makes a signing account look like an admin
//     can have it remove members; it cannot forge the signature.
//   - A replayed statement. A leave or a removal names an account, not an
//     epoch; a server that re-serves an old one after the account was added
//     back can have it removed again (availability, not confidentiality),
//     for as long as the statement is inside its 30-day window
//     (proto.MLSStatementMaxAgeSeconds, Q10).
//
// 임시, 정책 미충족 (legacy_temporary): a group created before 0.0.55 carries
// no roles until its owner's Commit sets them. Until then a received Add rests
// on its leaf alone, a Remove may rest on R3b (the server's signature), and a
// local Add or member Remove rests on user_initiated (the app's word). These
// are the paths marked legacyTemporary below; the status reports the group's
// authority so the app can say so.
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

// ErrStatementUnverified — a signed statement handed in for a local build does
// not verify. Nothing is built: a Commit carrying it would be refused by every
// receiver anyway.
var ErrStatementUnverified = errors.New("chat state refused a signed statement that does not verify")

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

// RemovedLeaf is one leaf a Commit removes: whose it is, and the declaration
// payload it carried, which holds the account key its own statements verify
// under.
type RemovedLeaf struct {
	AccountID   string
	DeviceID    string
	Declaration []byte
}

// RemovalEvidence verifies the signed statements a Commit carries in its
// authenticated data. Authorized has one entry per change.Removed: whether a
// statement covers removing that leaf. Invalid counts the statements present
// that do not verify, which a receiver ignores and a local build refuses.
type RemovalEvidence interface {
	Authorized(change CommitChange) (authorized []bool, invalid int, err error)
}

// CommitAuthority is the evidence a Commit is judged by beyond its own group
// state.
type CommitAuthority struct {
	// CommitMembers is the member set the server signed for the Commit being
	// judged, and CommitMembersKnown whether the row carried such a signature.
	// Read for legacy_temporary groups only (R3b).
	CommitMembers      []string
	CommitMembersKnown bool

	// Evidence verifies the statements the Commit carries. Nil verifies none.
	Evidence RemovalEvidence
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

func (s *Store) armAuthority(cipher any, members *ServerCommitMembers) {
	receiver, ok := cipher.(AuthorityReceiver)
	if !ok {
		return
	}
	var auth CommitAuthority
	if members != nil {
		auth.CommitMembers = slices.Clone(members.AccountIDs)
		auth.CommitMembersKnown = true
	}
	receiver.SetCommitAuthority(auth)
}

// CommitChange is what one Commit does, in accounts: who committed it (from
// the group's own tree, before the Commit), one entry per removed leaf, one
// per added leaf, how many proposals are neither, and what it does to the
// roles. Before is the account of every leaf of the tree it applies to.
type CommitChange struct {
	CommitterAccountID string
	CommitterDeviceID  string
	Removed            []string
	Added              []string
	OtherProposals     int

	// RemovedLeaves parallels Removed with what a statement is checked
	// against. Empty when the caller had nothing to check.
	RemovedLeaves []RemovedLeaf

	// CreatorAccountID is the account holding leaf 0 before the Commit: the
	// leaf of whoever created the group.
	CreatorAccountID string

	Epoch             uint64
	Before            []string
	RolesBefore       *Roles
	RolesChange       RolesChangeKind
	RolesAfter        *Roles
	AuthenticatedData []byte
}

// JudgeReceived holds a received Commit to the rules above. Nil means apply
// it; otherwise an *UnauthorizedCommitError naming the committer.
func JudgeReceived(change CommitChange, auth CommitAuthority) error {
	_, err := judge(change, auth, nil)
	return err
}

// judge is the one judgement behind a received Commit and a local build. plan
// is nil for a received Commit. The second result is the statements present
// that do not verify.
func judge(change CommitChange, auth CommitAuthority, plan *CommitPlan) (int, error) {
	refuse := func(reason string) error {
		return &UnauthorizedCommitError{
			CommitterAccountID: change.CommitterAccountID,
			CommitterDeviceID:  change.CommitterDeviceID,
			Reason:             reason,
		}
	}
	if change.OtherProposals > 0 {
		return 0, refuse("the commit carries a proposal other than add, remove and a roles change")
	}
	if reason := judgeRoles(change); reason != "" {
		return 0, refuse(reason)
	}
	authorized := make([]bool, len(change.Removed))
	invalid := 0
	if auth.Evidence != nil && len(change.Removed) > 0 {
		got, bad, err := auth.Evidence.Authorized(change)
		if err != nil {
			return 0, err
		}
		if len(got) == len(authorized) {
			authorized = got
		}
		invalid = bad
	}
	roles := change.effectiveRoles()
	asked := plan != nil && plan.UserInitiated
	for i, account := range change.Removed {
		switch {
		case account == change.CommitterAccountID: // R1
		case slices.Contains(change.Added, account): // R2
		case authorized[i]: // S
		case roleMayRemove(roles, change.CommitterAccountID, account) && (plan == nil || asked): // RR
		case roles == nil && plan == nil && change.legacyTemporaryR3b(auth, account):
		case roles == nil && asked: // legacyTemporary: R4i, the app's word
		default:
			return invalid, refuse("a remove is not the committer's own, not paired with an add, not signed, and not the committer's role to make")
		}
	}
	if plan == nil {
		return invalid, nil
	}
	for _, account := range change.Added {
		if !slices.Contains(change.Removed, account) && !asked {
			return invalid, refuse("an add needs a person on this device to ask for it")
		}
	}
	if change.RolesChange == RolesSet && change.RolesBefore != nil && !asked &&
		!change.isOwnerlessClaim(*change.RolesBefore, *change.RolesAfter) {
		return invalid, refuse("a roles change needs a person on this device to ask for it")
	}
	return invalid, nil
}

// legacyTemporaryR3b is R3b: in a group without roles, the member set the
// server signed for this Commit no longer holds the account. 임시, 정책 미충족.
func (c CommitChange) legacyTemporaryR3b(auth CommitAuthority, account string) bool {
	return auth.CommitMembersKnown && !slices.Contains(auth.CommitMembers, account)
}

// PlanJudge is a cipher that can describe, before building, the change a plan
// would make to the group it holds: the same CommitChange a receiver will
// read off the Commit.
type PlanJudge interface {
	PlanChange(plan CommitPlan) (CommitChange, error)

	// Evidence verifies the statements the plan's CommitAAD carries.
	Evidence() RemovalEvidence
}

// judgeLocalPlan holds a locally built plan to the rules above, before
// anything is built. A create is not judged here: it is the group's first
// Commit (CreateGroup never calls this), and the Rust rules hold it to the
// roles it sets. A replace is held to the permit's list first
// (requireListedReplacements), and a rejoin to its signed request by the
// caller.
func judgeLocalPlan(plan CommitPlan, cipher CommitCipher) error {
	pj, ok := cipher.(PlanJudge)
	if !ok {
		return nil
	}
	change, err := pj.PlanChange(plan)
	if err != nil {
		return err
	}
	invalid, err := judge(change, CommitAuthority{Evidence: pj.Evidence()}, &plan)
	if invalid > 0 {
		return ErrStatementUnverified
	}
	return err
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
