// commit.go — the Commit transactions, design §7.3.1 through §7.3.3.
//
// # What is being separated and why
//
// RFC 9420 §14: "The generation of Commit messages MUST NOT modify a client's
// state, since the client doesn't know at that time whether the changes implied
// by the Commit message will conflict with another Commit or not." Two members
// can build a Commit against the same epoch, and only one of them can be the
// epoch's. A device that has already moved its confirmed state has nowhere to
// go back to when it turns out to be the other one.
//
// So a built Commit lands in Record.Pending and in the library's pending slot,
// and the confirmed half of the record — Epoch, and the group state the send
// and receive paths encrypt and decrypt with — does not move. Exactly one call
// moves it, and only after the server has said which Commit its epoch accepted.
//
// # Who decides
//
// There is no delivery service here. The layer that picks one Commit per epoch
// is ariadne's compare-and-set on expected_epoch, and this package is the half
// that takes the verdict and applies it. It never infers the verdict: see the
// third outcome below.
//
// # The three outcomes (§7.3.2)
//
//	accepted    the pending becomes confirmed, Epoch becomes ExpectedEpoch+1,
//	            and the Welcome may be released for the first time
//	superseded  the pending is dropped with the next-epoch secrets in it, and
//	            the winner's Commit is applied to the state that never moved
//	unresolved  nothing. Not a guess, not a retry that assumes either way:
//	            the pending stays and every operation that would build on an
//	            undecided epoch is refused until the caller asks the server by
//	            ClientCommitID
//
// # The anchor (§7.3.3)
//
// Record.Epoch is the confirmed epoch and the anchor copies it. A pending
// Commit's epoch is never written there. If it were, losing a CAS would leave
// the next load seeing rec.Epoch < anchor.Epoch and latching the conversation
// on a rewind that never happened — a device would lock itself out of a
// conversation for losing a race it is supposed to lose sometimes.
//
// # Deliberately not here
//
// No group state, no Commit or Welcome bytes, and no length of any of them
// reaches a log or an error message. The serialized state carries this device's
// leaf signature secret key.

package chatstate

import (
	"errors"
)

// MaxCommitBytes bounds a Commit and a Welcome. A Commit carries a path update
// and a Welcome carries one encrypted group secret per added member, so both
// grow with the group; the ceiling is here so a record cannot be grown without
// limit by a caller that keeps building Commits for groups that do not exist.
const MaxCommitBytes = 262144

var (
	// ErrCommitPending — this conversation has a Commit whose outcome the
	// server has not settled. Building another one, or sending under an epoch
	// that may be about to change, would be acting on a guess.
	ErrCommitPending = errors.New("chat state has an unsettled commit for this conversation")

	// ErrNoPendingCommit — an outcome arrived for a conversation that is not
	// waiting on one.
	ErrNoPendingCommit = errors.New("chat state has no pending commit to settle")

	// ErrCommitMismatch — the outcome names a different Commit than the one
	// this device is waiting on. Settling on it would apply a verdict about
	// somebody else's attempt to ours.
	ErrCommitMismatch = errors.New("chat state pending commit does not match this outcome")
)

// CommitCipher is the MLS half of building and settling one Commit. Every
// method runs inside the conversation lock, as SendCipher's do, and for the
// same reason: the record is the authority on where the group is, so a session
// carried across a lock release is a copy with nothing protecting it.
type CommitCipher interface {
	// Load restores the session from the record's stored state, including any
	// pending Commit that state carries.
	Load(groupState []byte) error

	// BuildCommit produces a Commit without applying it. It must fail rather
	// than replace one that is already pending.
	BuildCommit(plan CommitPlan) (BuiltCommit, error)

	// ApplyPending promotes the pending Commit to confirmed.
	ApplyPending() error

	// ClearPending drops the pending Commit and the next-epoch secrets in it.
	ClearPending() error

	// ApplyMessage applies somebody else's Commit and reports the epoch it
	// produced and whether it removed this device. It also clears any pending
	// Commit, which is what makes losing a race a single operation.
	ApplyMessage(message []byte) (epoch uint64, removed bool, err error)

	// Epoch is the confirmed epoch, never one only a pending Commit reaches.
	Epoch() (uint64, error)

	// State serializes the session. Nothing the MLS library did is durable
	// until what this returns is written.
	State() ([]byte, error)

	// ConfirmedAccounts must not see a pending Commit. It is what keeps a
	// built Remove from unlatching anything before the server accepts it.
	RosterReader
}

// CommitPlan is what one Commit should contain. Empty means a Commit with no
// proposals, which rotates this device's own key material. A plan adds or
// removes, not both.
type CommitPlan struct {
	AddKeyPackages [][]byte

	// RemoveAccountIDs takes every leaf of each account out of the group:
	// leaving the organization removes a person, not one of their devices.
	RemoveAccountIDs []string
}

// BuiltCommit is what the MLS layer produced for a plan.
type BuiltCommit struct {
	Commit  []byte
	Welcome []byte

	// ExpectedEpoch is the confirmed epoch this Commit was built against, and
	// therefore the value the server's compare-and-set is against.
	ExpectedEpoch uint64
}

// BeginCommitRequest is one attempt at an epoch.
type BeginCommitRequest struct {
	// ClientCommitID is the server's idempotency key and the question a device
	// asks when it never heard the answer. The caller mints it.
	ClientCommitID string

	Plan CommitPlan
}

// BeginCommitResult is what the caller posts to the server's CAS endpoint.
type BeginCommitResult struct {
	ClientCommitID string
	ExpectedEpoch  uint64
	Commit         []byte

	// Welcome is the message for the members this Commit adds. It travels to
	// the server in the same request as the Commit so that the two land in one
	// row, and the server serves it to a joiner only for a row that won its
	// epoch. Until then WelcomeReleasable is false and no caller may deliver
	// it (RFC 9420 §14).
	Welcome           []byte
	WelcomeReleasable bool

	// Created is false when this call answered from a Commit that was already
	// pending under the same id. A lost response is retried, not rebuilt.
	Created bool

	Generation uint64
}

// CommitOutcomeKind is the server's verdict.
type CommitOutcomeKind string

const (
	// CommitAccepted — the CAS succeeded and this Commit is the epoch's.
	CommitAccepted CommitOutcomeKind = "accepted"

	// CommitSuperseded — the CAS returned 409 and another Commit took the
	// epoch. The winner's message settles it.
	CommitSuperseded CommitOutcomeKind = "superseded"
)

// CommitOutcome carries one verdict back from the server. There is no third
// value for "unknown": an unknown outcome is the absence of this call.
type CommitOutcome struct {
	ClientCommitID string
	Kind           CommitOutcomeKind

	// WinnerMessage is the Commit that took the epoch, required for
	// CommitSuperseded. Applying it here rather than through Receive is what
	// keeps the losing device's discard and the winner's application inside
	// one lock and one file replacement.
	WinnerMessage []byte
}

// ConfirmCommitResult is the state after the verdict.
type ConfirmCommitResult struct {
	// Epoch is the confirmed epoch, which has moved in both outcomes: to the
	// pending Commit's epoch when accepted, to the winner's when superseded.
	Epoch uint64

	// Welcome is non-nil only for an accepted Commit that added members.
	Welcome           []byte
	WelcomeReleasable bool

	// Removed reports a winning Commit that took this device out of the group.
	Removed bool

	Generation uint64
}

// BeginCommit builds a Commit and stores it as pending. The confirmed state
// does not move and the caller must not act as though it had.
//
// One transaction, one file replacement: the group state carrying the fork and
// the record's note of it land together, so a crash leaves a conversation that
// either has an unsettled Commit or does not, never a fork with nothing saying
// so.
func (s *Store) BeginCommit(
	conversationID string, wm ServerWatermark, req BeginCommitRequest, cipher CommitCipher,
) (BeginCommitResult, error) {
	if req.ClientCommitID == "" {
		return BeginCommitResult{}, errors.New("commit needs a client commit id")
	}
	var out BeginCommitResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending != nil {
			// The same id is a retry of a call whose answer was lost, and it
			// gets the stored bytes. A different id is a second fork, which is
			// what §7.3.1 refuses and what the library refuses under it.
			if rec.Pending.ClientCommitID != req.ClientCommitID {
				return ErrCommitPending
			}
			out = pendingResult(*rec.Pending, rec.Generation, false)
			return nil
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		// Never a refusal here, whatever is latched: a Remove Commit is the
		// only way a latched conversation gets out (§6.4.1 condition 2). The
		// judgement still runs so this permit's list is not lost, and it runs
		// before the build so that it reads the roster the Commit forks from.
		latch, err := judgeRemovals(rec.RemovalLatch, wm.PendingRemovals, cipher)
		if err != nil {
			return err
		}
		built, err := cipher.BuildCommit(req.Plan)
		if err != nil {
			return err
		}
		if len(built.Commit) == 0 || len(built.Commit) > MaxCommitBytes ||
			len(built.Welcome) > MaxCommitBytes {
			return errors.New("mls commit or welcome is outside the size bound")
		}
		state, err := cipher.State()
		if err != nil {
			return err
		}
		pending := PendingCommit{
			ClientCommitID: req.ClientCommitID,
			ExpectedEpoch:  built.ExpectedEpoch,
			Commit:         built.Commit,
			Welcome:        built.Welcome,
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = &pending
		rec.RemovalLatch = latch
		// Record.Epoch is deliberately untouched. commit() copies it into the
		// anchor, and a pending epoch written there would make the next load
		// read a lost race as a rewind (§7.3.3).
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = pendingResult(pending, rec.Generation, true)
		return nil
	})
	return out, err
}

// ConfirmCommit applies the server's verdict. It is the only call that moves
// the confirmed epoch of a Commit this device built.
func (s *Store) ConfirmCommit(
	conversationID string, wm ServerWatermark, outcome CommitOutcome, cipher CommitCipher,
) (ConfirmCommitResult, error) {
	switch outcome.Kind {
	case CommitAccepted:
	case CommitSuperseded:
		if len(outcome.WinnerMessage) == 0 {
			return ConfirmCommitResult{}, errors.New("a superseded commit needs the winning message")
		}
	default:
		return ConfirmCommitResult{}, errors.New("commit outcome must be accepted or superseded")
	}
	var out ConfirmCommitResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending == nil {
			return ErrNoPendingCommit
		}
		pending := *rec.Pending
		if pending.ClientCommitID != outcome.ClientCommitID {
			return ErrCommitMismatch
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}

		var (
			epoch   uint64
			removed bool
			welcome []byte
		)
		if outcome.Kind == CommitAccepted {
			if err := cipher.ApplyPending(); err != nil {
				return err
			}
			if epoch, err = cipher.Epoch(); err != nil {
				return err
			}
			welcome = pending.Welcome
		} else {
			// Order matters and is one operation in the library: applying the
			// winner runs on the state that never moved, and it drops our fork
			// as it goes. ClearPending first would work too, but only this way
			// is there no moment where the fork is gone and the winner is not
			// yet applied.
			if epoch, removed, err = cipher.ApplyMessage(outcome.WinnerMessage); err != nil {
				return err
			}
			// Normally a no-op: mls-rs drops the pending as part of
			// applying another member's Commit. It is here because "the fork
			// is gone" has to be true when this transaction writes, not
			// merely likely.
			if err := cipher.ClearPending(); err != nil {
				return err
			}
		}

		// Whichever Commit took the epoch is now the confirmed state, so this
		// is the judgement that can finally unlatch. A winner that did not
		// remove the leaf leaves the account latched: losing the race to
		// someone else's Commit is not the same as the removal happening.
		latch := rec.RemovalLatch
		if !removed {
			if latch, err = judgeRemovals(rec.RemovalLatch, wm.PendingRemovals, cipher); err != nil {
				return err
			}
		}

		state, err := cipher.State()
		if err != nil {
			return err
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = nil
		rec.RemovalLatch = latch
		rec.enterEpoch(epoch)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = ConfirmCommitResult{
			Epoch:             rec.Epoch,
			Welcome:           welcome,
			WelcomeReleasable: outcome.Kind == CommitAccepted && len(welcome) > 0,
			Removed:           removed,
			Generation:        rec.Generation,
		}
		return nil
	})
	return out, err
}

// PendingCommit reports the unsettled Commit so the caller can ask the server
// what became of it. It answers with the bytes to repost and deliberately not
// with the Welcome: until the server says this Commit was accepted, there is no
// epoch for a joiner to be welcomed into (RFC 9420 §14).
func (s *Store) PendingCommit(
	conversationID string, wm ServerWatermark,
) (PendingCommit, bool, error) {
	var (
		pending PendingCommit
		ok      bool
	)
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending == nil {
			return nil
		}
		pending, ok = *rec.Pending, true
		pending.Welcome = nil
		return nil
	})
	return pending, ok, err
}

func pendingResult(pending PendingCommit, generation uint64, created bool) BeginCommitResult {
	return BeginCommitResult{
		ClientCommitID: pending.ClientCommitID,
		ExpectedEpoch:  pending.ExpectedEpoch,
		Commit:         pending.Commit,
		Welcome:        pending.Welcome,
		// Never true here. The Commit has not been accepted yet, and this is
		// the whole of the rule RFC 9420 §14 states alongside the one about
		// not modifying state.
		WelcomeReleasable: false,
		Created:           created,
		Generation:        generation,
	}
}
