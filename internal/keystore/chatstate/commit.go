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
	"fmt"
	"slices"
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

	// The exporter is how a Commit carries a room's name into the epoch it
	// creates (roomname.go).
	RoomNameExporter
}

// CommitPlan is what one Commit should contain. Empty means a Commit with no
// proposals, which rotates this device's own key material. A plan adds,
// removes or replaces: one kind, never two.
type CommitPlan struct {
	AddKeyPackages [][]byte

	// RemoveAccountIDs takes every leaf of each account out of the group:
	// leaving the organization removes a person, not one of their devices.
	RemoveAccountIDs []string

	// Replace swaps each account's leaves for the leaf of the device that took
	// it over (design M4.4), in one Commit.
	Replace []ReplaceMember

	// Rejoin re-seats each account whose every Welcome was unusable: every
	// leaf it holds goes out and its new KeyPackage comes in, in one Commit
	// (R2). The caller has already verified each account's signed request.
	Rejoin []RejoinMember

	// UserInitiated says a person on this device asked for this Add or
	// Remove (R4i, authority.go). Automation never sets it. It is the app's
	// word, not something the Keeper can check.
	UserInitiated bool
}

// RejoinMember is one account to re-seat and the KeyPackage its signed rejoin
// request names the leaf of.
type RejoinMember struct {
	AccountID  string
	KeyPackage []byte
}

// ReplaceMember is one account to replace. NewFingerprint is the one the
// permit named for the account, never one the caller picked, and the
// KeyPackage's leaf must sign with exactly that key.
//
// Handover is the old device's approval of the succession (succession.go),
// nil for an account recovery, which then needs UserInitiated.
type ReplaceMember struct {
	AccountID      string
	NewFingerprint string
	KeyPackage     []byte
	Handover       *LeafHandover
}

// ErrReplacementNotListed — a replace plan names an account, or a key for it,
// that this operation's permit does not list as taken over. The permit is the
// only statement of which key replaces an account, so a replacement it does not
// name is not built.
var ErrReplacementNotListed = errors.New("chat state replace plan names a replacement the permit does not list")

// requireListedReplacements holds every replace entry to the permit's list.
func requireListedReplacements(plan CommitPlan, wm ServerWatermark) error {
	for _, m := range plan.Replace {
		if !slices.Contains(wm.PendingLeafReplacements,
			LeafReplacement{AccountID: m.AccountID, NewFingerprint: m.NewFingerprint}) {
			return ErrReplacementNotListed
		}
	}
	return nil
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

	// ExpectedEpoch refuses a build when the confirmed epoch is another one,
	// before anything is built. Zero asserts nothing, as in SendRequest.
	ExpectedEpoch uint64

	// RoomName, when set, is resealed for the epoch the Commit creates, from
	// the pending Commit and before the CAS, so the server can store it with
	// the Commit in one row. The caller owns and wipes it.
	RoomName []byte

	// AppContext is stored with the pending Commit (PendingCommit.AppContext).
	// A retry keeps the first build's.
	AppContext []byte
}

// MaxPendingAppContextBytes bounds PendingCommit.AppContext. The app's
// description of a Commit names at most a room's members and their claimed
// KeyPackages; the bound keeps a caller from growing the record with it.
const MaxPendingAppContextBytes = 65536

func checkAppContext(context []byte) error {
	if len(context) > MaxPendingAppContextBytes {
		return fmt.Errorf("app context is over %d bytes", MaxPendingAppContextBytes)
	}
	return nil
}

func storedName(name *SealedRoomName) *PendingRoomName {
	if name == nil {
		return nil
	}
	return &PendingRoomName{IV: name.IV, Ciphertext: name.Ciphertext}
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

	// RoomName is the request's name sealed for ExpectedEpoch+1, or nil.
	// A retry seals it again under a fresh IV; either answer opens.
	RoomName *SealedRoomName
}

// resealPending answers a retried build's room name from the stored pending
// Commit. Nothing is written.
func resealPending(conversationID string, rec *Record, name []byte, cipher CommitCipher) (*SealedRoomName, error) {
	if name == nil {
		return nil, nil
	}
	if err := cipher.Load(rec.GroupState); err != nil {
		return nil, err
	}
	return sealForPending(cipher, conversationID, rec.Pending.ExpectedEpoch, name)
}

func checkRoomName(name []byte) error {
	if name == nil {
		return nil
	}
	return validRoomName(name)
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

	// WinnerMembers verifies the member set the server signed for the winning
	// Commit against the epoch it produces, which only the pending Commit
	// here knows, and returns it. Nil when the winner's row carried none.
	WinnerMembers func(epoch uint64) (*ServerCommitMembers, error)
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

	// Winner is what the winning Commit of a superseded outcome did, in
	// accounts, so a caller whose Commit lost can tell whether the winner
	// touched the accounts it was about (Q20). Nil when accepted, or when the
	// cipher does not report it.
	Winner *CommitChange

	Generation uint64
}

// ChangeReporter is a cipher that reports what the last Commit it applied did.
type ChangeReporter interface {
	LastCommitChange() (CommitChange, bool)
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
	if err := checkRoomName(req.RoomName); err != nil {
		return BeginCommitResult{}, err
	}
	if err := checkAppContext(req.AppContext); err != nil {
		return BeginCommitResult{}, err
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
			name, err := resealPending(conversationID, rec, req.RoomName, cipher)
			if err != nil {
				return err
			}
			out = pendingResult(*rec.Pending, rec.Generation, false)
			out.RoomName = name
			return nil
		}
		// After the retry branch: a retry answers with bytes already built,
		// and the permit it arrives with may have dropped the entry since.
		if err := requireListedReplacements(req.Plan, wm); err != nil {
			return err
		}
		if err := requireAuthorizedPlan(req.Plan, rec, wm); err != nil {
			return err
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		if req.ExpectedEpoch != 0 {
			epoch, err := cipher.Epoch()
			if err != nil {
				return err
			}
			if epoch != req.ExpectedEpoch {
				return ErrEpochStale
			}
		}
		// Never a refusal here, whatever is latched: a Remove or replace
		// Commit is the only way a latched conversation gets out (§6.4.1
		// condition 2, M4.4). The judgement still runs so this permit's lists
		// are not lost, and it runs before the build so that it reads the
		// roster the Commit forks from.
		latch, err := judgeLatches(rec, wm, cipher)
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
		// Before the write, so a name that cannot be resealed persists no
		// Commit either.
		var name *SealedRoomName
		if req.RoomName != nil {
			if name, err = sealForPending(cipher, conversationID, built.ExpectedEpoch, req.RoomName); err != nil {
				return err
			}
		}
		pending := PendingCommit{
			ClientCommitID: req.ClientCommitID,
			ExpectedEpoch:  built.ExpectedEpoch,
			Commit:         built.Commit,
			Welcome:        built.Welcome,
			AppContext:     req.AppContext,
			Name:           storedName(name),
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = &pending
		latch.apply(rec)
		// Record.Epoch is deliberately untouched. commit() copies it into the
		// anchor, and a pending epoch written there would make the next load
		// read a lost race as a rewind (§7.3.3).
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = pendingResult(pending, rec.Generation, true)
		out.RoomName = name
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
			winner  *CommitChange
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
			var members *ServerCommitMembers
			if outcome.WinnerMembers != nil {
				if members, err = outcome.WinnerMembers(pending.ExpectedEpoch + 1); err != nil {
					return err
				}
			}
			s.armAuthority(cipher, rec, wm, members)
			// Order matters and is one operation in the library: applying the
			// winner runs on the state that never moved, and it drops our fork
			// as it goes. ClearPending first would work too, but only this way
			// is there no moment where the fork is gone and the winner is not
			// yet applied.
			if epoch, removed, err = cipher.ApplyMessage(outcome.WinnerMessage); err != nil {
				return latchIfRefused(s, p, anchor, err, pending.ExpectedEpoch+1)
			}
			if reporter, ok := cipher.(ChangeReporter); ok {
				if change, ok := reporter.LastCommitChange(); ok {
					winner = &change
				}
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
		latch := storedLatches(rec)
		if !removed {
			if latch, err = judgeLatches(rec, wm, cipher); err != nil {
				return err
			}
		}

		state, err := cipher.State()
		if err != nil {
			return err
		}
		crashAt(CrashConfirmAfterApply)
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = nil
		latch.apply(rec)
		rec.enterEpoch(epoch)
		if outcome.Kind == CommitAccepted {
			rec.noteConfirmed(pending.ExpectedEpoch+1, pending.Commit)
		} else {
			rec.noteConfirmed(pending.ExpectedEpoch+1, outcome.WinnerMessage)
		}
		if removed {
			rec.RemovedFromGroup = true
		}
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		out = ConfirmCommitResult{
			Epoch:             rec.Epoch,
			Welcome:           welcome,
			WelcomeReleasable: outcome.Kind == CommitAccepted && len(welcome) > 0,
			Removed:           removed,
			Winner:            winner,
			Generation:        rec.Generation,
		}
		return nil
	})
	return out, err
}

// latchIfRefused latches the conversation when err is the authority rules
// refusing a received Commit (Q4), and passes any other error through. The
// latch is the anchor's alone: the record is not written, so the Commit is
// not applied and whatever was pending stays as it was.
func latchIfRefused(s *Store, p convPaths, anchor Anchor, err error, epoch uint64) error {
	var refused *UnauthorizedCommitError
	if !errors.As(err, &refused) {
		return err
	}
	return s.latchRekeyDetail(p.tag, anchor, RekeyDetail{
		Cause:              RekeyCauseUnauthorizedCommit,
		Epoch:              epoch,
		CommitterAccountID: refused.CommitterAccountID,
		CommitterDeviceID:  refused.CommitterDeviceID,
	})
}

// ErrNotLegacyPending — the pending Commit carries the app's description of
// it (built by 0.0.55 or later), so the app can post it again; abandoning it
// would throw away a Commit that can still be settled.
var ErrNotLegacyPending = errors.New("chat state pending commit carries an app context and can be reposted")

// AbandonCipher is what AbandonLegacyPending needs from MLS.
type AbandonCipher interface {
	Load(groupState []byte) error
	ClearPending() error
	State() ([]byte, error)
}

// AbandonLegacyPending drops a pending Commit that was built before the app
// could describe it (no AppContext), on the user's confirmation (design Q23).
// Nothing can post such a Commit again once the app lost its own note of it,
// so without this the conversation is commit_pending for good.
//
// Only the pending fork goes: the confirmed epoch, the latches and the history
// stay, and the anchor does not move. The caller is the one that asked the
// server first: the handshake log holds no row at ExpectedEpoch+1, so the
// Commit never won its epoch. What this cannot rule out, and states: a post of
// these bytes still in flight from an app that has since died could still
// land; this device would then refuse its own Commit on catch-up.
func (s *Store) AbandonLegacyPending(
	conversationID string, wm ServerWatermark, clientCommitID string, cipher AbandonCipher,
) (uint64, error) {
	if clientCommitID == "" {
		return 0, errors.New("abandon needs a client commit id")
	}
	var generation uint64
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		if rec.Pending == nil {
			return ErrNoPendingCommit
		}
		if rec.Pending.ClientCommitID != clientCommitID {
			return ErrCommitMismatch
		}
		if len(rec.Pending.AppContext) > 0 {
			return ErrNotLegacyPending
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}
		if err := cipher.ClearPending(); err != nil {
			return err
		}
		state, err := cipher.State()
		if err != nil {
			return err
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.Pending = nil
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		generation = rec.Generation
		return nil
	})
	return generation, err
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
