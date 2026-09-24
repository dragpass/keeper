// receive.go — the receive transaction, design §7.2.2 and §8.4.
//
// # Not a mirror of the send
//
// The send's problem is that a position must not be used twice. The receive's
// problem is the opposite shape: a decrypt consumes the key and RFC 9420 §9.2
// requires it to be deleted at once, so a success cannot be repeated. If the
// process dies between "the decrypt succeeded" and "the app has the plaintext",
// the message is gone — the key is deleted, and the server's ciphertext is no
// longer openable by this device or any other.
//
// So the boundary here is atomicity rather than ordering. The advanced group
// state, the delivery mark and a sealed copy of the plaintext are one file
// replacement. After a crash a restart sees all three or none, and a re-read is
// answered from the sealed copy rather than from the wire.
//
// # Where a refusal leaves things
//
// A message that decrypts but fails the generation check is not confirmed at
// all: nothing is written, the plaintext is wiped, and the error goes back
// bare. That leaves the disk believing a key the library has already consumed
// is still unused, which is stated rather than hidden. It is the safe
// direction of the two. Re-deriving a decryption key for the same ciphertext
// is not the reuse this design cannot take back — that one is on the send side
// — whereas confirming a receive whose plaintext is refused would leave a state
// advance with no history entry behind it, which is exactly the half-written
// pair §8.4 forbids.
//
// # Deliberately not here
//
// No plaintext, no sealed bytes, no group state and no buffer length reaches a
// log or an error message.

package chatstate

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/dragpass/keeper/internal/keystore/secure"
)

// Opened is what the MLS layer reports about one inbound message.
type Opened struct {
	Epoch           uint64
	SenderLeafIndex uint32
	Application     bool
	Removed         bool

	// AuthenticatedData is the sender's cleartext declaration, covered by the
	// sender's signature and by the AEAD tag.
	AuthenticatedData []byte

	// KeyGeneration is the generation the library actually derived keys from.
	//
	// Nil means the library could not report it, and nil is carried as nil.
	// Upstream reaches its None by folding an extraction error into a default,
	// so a zero substituted here would make "checked and it matched" and "never
	// looked" the same answer.
	KeyGeneration *uint32

	// SenderAccountID and SenderDeviceID are the credential of the leaf that
	// sent an application message, read from the group's own tree and never
	// from the server. Empty for anything else.
	SenderAccountID string
	SenderDeviceID  string

	// Plaintext is set for an application message. The caller of Open keeps
	// ownership; this package wipes it before returning on every path that
	// does not hand it back.
	Plaintext []byte
}

// ReceiveCipher is the MLS half of one delivery.
type ReceiveCipher interface {
	// Load restores the session from the record's stored state, inside the
	// lock, for the same reason SendCipher.Load is called there.
	Load(groupState []byte) error

	// Open decrypts or applies one inbound message. The key it used is
	// consumed by the time this returns.
	Open(message []byte) (Opened, error)

	// State serializes the session as it now stands.
	State() ([]byte, error)

	// ConfirmedAccounts is read after Open, so a Commit that Open applied is
	// already part of the roster it reports.
	RosterReader
}

// ReceiveRequest is one inbound message. Seq is the server's sequence, which
// is what a re-read asks by and what the local history is keyed on.
type ReceiveRequest struct {
	Seq     uint64
	Message []byte

	// Handshake marks a Commit taken from the server's handshake log, and
	// ProducedEpoch is the epoch that log says it produced. Together they are
	// the ordering rule for handshakes: the one applied next must produce the
	// epoch after the confirmed one, no earlier and no later.
	//
	// The rule is on epochs and not on Seq because the server numbers
	// handshakes and application messages on one gap-free axis, so a gap
	// between two handshake seqs is ordinary and says nothing about a
	// handshake having been skipped. The epoch does: the server keeps one
	// handshake per epoch, and MLS binds the epoch into the Commit it
	// authenticates, so the claimed value is checked against what applying
	// the Commit actually produced before anything is written.
	Handshake     bool
	ProducedEpoch uint64

	// CommitMembers is the member set the server signed for this handshake's
	// Commit, already verified by the caller, and nil when the row carried
	// none. It is evidence for the authority rules (authority.go).
	CommitMembers *ServerCommitMembers

	// FramedEpoch is the epoch an application message's cleartext header
	// claims (mls.PrivateMessageEpoch), nil when the caller did not read it.
	// A display batch uses it for one thing: a message from before the epoch
	// this device's leaf entered the group at is answered as BeforeJoin
	// instead of being handed to MLS, which has no key for it.
	FramedEpoch *uint64
}

// Sender is who sent an application message, as the MLS credential of the
// sending leaf named them.
type Sender struct {
	AccountID string
	DeviceID  string
}

// ReceiveResult is what the caller may show.
type ReceiveResult struct {
	Plaintext   []byte
	Application bool
	Removed     bool
	Position    Position

	// Sender is set for an application message, from the credential at the
	// first delivery and from the sealed copy on a re-read.
	Sender Sender

	// FirstDelivery is false when this position was already marked.
	FirstDelivery bool

	// FromHistory is true when the plaintext came out of the local sealed copy
	// and no MLS key was touched. A re-read is always this.
	FromHistory bool

	// OwnWithoutCopy is true for a message this device sent whose seq has no
	// sealed copy here, and none that bindUnmarkedSent could bind. There is no plaintext and no position, and nothing was
	// consumed or written for it. Only ReceiveBatch reports it.
	OwnWithoutCopy bool

	// HistoryUnavailable is true for a seq MLS already opened on this device
	// whose sealed copy is no longer held: the ring evicted it. Its key was
	// consumed at that first delivery, so there is no plaintext, no position
	// and no sender, and nothing was opened or written for it. Only
	// ReceiveBatch reports it.
	HistoryUnavailable bool

	// BeforeJoin is true for a seq this device never opened whose message
	// claims an epoch before Record.OwnLeaf.SinceEpoch: it was sent to the
	// group before this device's leaf was in it, so this device never held
	// its key. Not an error and not lost history. No plaintext, no position,
	// no sender, and nothing was opened or written for it. Only ReceiveBatch
	// reports it.
	BeforeJoin bool

	// Generation is the record's write counter after the confirmation, or the
	// current one when nothing was written.
	Generation uint64
}

var (
	// ErrHandshakeApplied — the handshake produces an epoch this record is
	// already at or past. A redelivery, or this device's own accepted Commit
	// coming back from the log.
	ErrHandshakeApplied = errors.New("chat state is already past the epoch this handshake produces")

	// ErrHandshakeSkipped — the handshake produces an epoch more than one past
	// the confirmed one, so at least one handshake before it was not applied.
	ErrHandshakeSkipped = errors.New("chat state has not applied the handshake before this one")

	// ErrNotHandshake — a message handed in as a handshake decrypted as an
	// application message. Nothing was written.
	ErrNotHandshake = errors.New("chat state was handed an application message as a handshake")
)

// ErrOwnMessage — the MLS layer refused a message because this device's own
// leaf sent it (mls-rs CantProcessMessageFromSelf). The refusal comes from
// reading the sender data, before any content key is derived, so nothing was
// consumed. ReceiveBatch answers it from the sealed copy or as OwnWithoutCopy;
// everywhere else it is a refusal like any other.
var ErrOwnMessage = errors.New("chat state was handed a message this device sent")

// ErrHistoryUnavailable — the sealed copy for this sequence is not there, or
// cannot say who sent it. A re-read of a message whose history has been
// evicted, expired or damaged ends here, and it is terminal: the MLS key for it was consumed and deleted when it
// was first delivered, so the server's ciphertext cannot stand in.
var ErrHistoryUnavailable = errors.New("chat state has no local copy of that message")

// errOpenedWithoutCopy is ErrHistoryUnavailable for a seq Record.OpenedSeqs
// says was opened here: the one form of it ReceiveBatch answers per item
// rather than refusing the page. A copy that is present but cannot say who
// sent it stays a refusal.
var errOpenedWithoutCopy = fmt.Errorf("%w: it was opened here and its copy is gone", ErrHistoryUnavailable)

// errBeforeJoin — the message claims an epoch before this device's leaf
// entered the group (ReceiveResult.BeforeJoin). ReceiveBatch answers it per
// item.
var errBeforeJoin = errors.New("chat state was handed a message from before this device joined")

// beforeJoin reports whether a message claiming framedEpoch was sent before
// this device's leaf entered the group. A record with no OwnLeaf (written
// before it existed) cannot say, and the message goes to MLS as before.
func (r *Record) beforeJoin(framedEpoch *uint64) bool {
	return framedEpoch != nil && r.OwnLeaf != nil && *framedEpoch < r.OwnLeaf.SinceEpoch
}

// Receive confirms one inbound message and returns its plaintext.
//
// A sequence already in the local history is answered from there: no MLS call,
// no state change, nothing written. That is the re-read path, and it is the
// only one there is — the message key is long gone.
func (s *Store) Receive(
	conversationID string, wm ServerWatermark, req ReceiveRequest, cipher ReceiveCipher,
) (ReceiveResult, error) {
	if len(req.Message) == 0 {
		return ReceiveResult{}, errors.New("receive needs a message")
	}
	var out ReceiveResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if err != nil {
			return err
		}
		loaded := rec.Generation
		var changed bool
		out, changed, err = s.receiveOne(conversationID, rec, wm, req, cipher, nil)
		var fork *forkDetected
		if errors.As(err, &fork) {
			return s.latchRekeyDetail(p.tag, anchor, RekeyDetail{Cause: RekeyCauseFork, Epoch: fork.epoch})
		}
		if err != nil {
			return blockIfRefused(s, p, anchor, err, req.ProducedEpoch, req.Message)
		}
		if !changed {
			return nil
		}
		if req.Handshake {
			crashAt(CrashProcessAfterApply)
		}
		// One replacement carries the advanced state, the mark and the sealed
		// copy. There is no arrangement of these three that can be observed
		// half-done, which is what §8.4's first condition asks for.
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			secure.Zeroize(out.Plaintext)
			return err
		}
		out.Generation = rec.Generation
		return nil
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	return out, nil
}

// MaxReceiveBatch bounds one ReceiveBatch: the display page the app asks for.
const MaxReceiveBatch = 200

// ReceiveBatch confirms a page of application messages as one transaction:
// every message is opened, checked and sealed into the history in memory, and
// the record is replaced once at the end. One refusal anywhere — a message that
// does not open, a declaration that does not match, something that is not an
// application message, or accept saying no — writes nothing and returns no
// plaintext at all.
//
// One outcome is not a refusal: a message this device sent, whose seq has no
// sealed copy here. MLS will not open a message from its own leaf, so the
// sealed copy is the only place its plaintext could come from. When MarkSent
// never ran and the row's bytes are those of our own outbox entry, the copy is
// bound to the seq here and shown from history (bindUnmarkedSent). Otherwise —
// the copy was evicted, or it never existed — its absence is a fact about this
// device's history and not a sign that anything is wrong with the page. It is
// answered as OwnWithoutCopy, with no plaintext, and the rest of the batch
// proceeds. The exception is exactly ErrOwnMessage from Open: a message that
// fails for any other reason, including one that only claims to be ours, still
// refuses the batch. A member who forges sender data naming this device's leaf
// gets a placeholder shown under this device's name and no content, which is
// no more than it could do by sending garbage.
//
// A refused batch leaves the disk believing the keys of the messages before
// the refusal are unused, although the library consumed them in memory. That
// is the direction receive.go already takes for a refused message, for the
// same reason: re-deriving a decryption key for one ciphertext is not the reuse
// this design cannot take back, and confirming a delivery whose plaintext the
// caller never got would be.
//
// accept sees each new plaintext before it is sealed; nil accepts everything.
// Re-reads from the history are not shown to it: they were accepted when they
// were first delivered.
//
// A second outcome is not a refusal either: a seq MLS already opened here
// whose copy the ring has since evicted. Its key is gone, so it is never
// handed to Open again; it is answered as HistoryUnavailable, with no
// plaintext, and the rest of the batch proceeds. Record.OpenedSeqs is what
// tells it apart from a message nobody has opened yet, which still goes to
// Open.
//
// A third: a seq never opened here whose message claims an epoch before the
// one this device's leaf entered the group at (Record.beforeJoin). This device
// never held its key, so it is not handed to Open; it is answered as
// BeforeJoin and the rest of the batch proceeds. The claim is the cleartext
// header's and is not authenticated. Believing a false one hides one message
// from this device, which the server could do by not serving it.
//
// On a conversation latched NeedsRekey a batch made only of re-reads is still
// answered, from the history and without MLS (loadLatched), an evicted seq as
// HistoryUnavailable and a pre-join one as BeforeJoin. A batch holding even
// one other sequence that was never opened here is refused whole with
// ErrRekeyRequired, by the same all-or-nothing rule.
func (s *Store) ReceiveBatch(
	conversationID string, wm ServerWatermark, reqs []ReceiveRequest,
	accept func(plaintext []byte) error, cipher ReceiveCipher,
) ([]ReceiveResult, error) {
	if len(reqs) == 0 || len(reqs) > MaxReceiveBatch {
		return nil, errors.New("receive batch size is out of range")
	}
	seen := make(map[uint64]bool, len(reqs))
	for _, req := range reqs {
		if len(req.Message) == 0 || req.Handshake || seen[req.Seq] {
			return nil, errors.New("receive batch needs distinct application messages")
		}
		seen[req.Seq] = true
	}
	out := make([]ReceiveResult, 0, len(reqs))
	wipe := func() {
		for _, r := range out {
			secure.Zeroize(r.Plaintext)
		}
	}
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, anchor, err := s.loadChecked(p, conversationID, wm)
		if errors.Is(err, ErrRekeyRequired) {
			rec, err = s.loadLatched(p, conversationID)
			if err != nil {
				return err
			}
			for _, req := range reqs {
				stored, ok := rec.findHistory(req.Seq)
				if !ok && rec.opened(req.Seq, s.HistoryPolicy) {
					out = append(out, ReceiveResult{Application: true, HistoryUnavailable: true, Generation: rec.Generation})
					continue
				}
				if !ok && rec.beforeJoin(req.FramedEpoch) {
					out = append(out, ReceiveResult{Application: true, BeforeJoin: true, Generation: rec.Generation})
					continue
				}
				if !ok {
					return ErrRekeyRequired
				}
				result, err := s.reread(conversationID, rec, stored)
				if err != nil {
					return err
				}
				out = append(out, result)
			}
			return nil
		}
		if err != nil {
			return err
		}
		loaded := rec.Generation
		changed := false
		for _, req := range reqs {
			result, wrote, err := s.receiveOne(conversationID, rec, wm, req, cipher, accept)
			if errors.Is(err, ErrOwnMessage) {
				bound, ok, err := s.bindUnmarkedSent(conversationID, rec, req)
				if err != nil {
					return err
				}
				if !ok {
					bound = ReceiveResult{Application: true, OwnWithoutCopy: true, Generation: rec.Generation}
				}
				out = append(out, bound)
				changed = changed || ok
				continue
			}
			if errors.Is(err, errOpenedWithoutCopy) {
				out = append(out, ReceiveResult{Application: true, HistoryUnavailable: true, Generation: rec.Generation})
				continue
			}
			if errors.Is(err, errBeforeJoin) {
				out = append(out, ReceiveResult{Application: true, BeforeJoin: true, Generation: rec.Generation})
				continue
			}
			if err != nil {
				return err
			}
			if !result.Application {
				return ErrNotApplication
			}
			out = append(out, result)
			changed = changed || wrote
		}
		if !changed {
			return nil
		}
		crashAt(CrashReceiveBatchAfterOpen)
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}
		for i := range out {
			out[i].Generation = rec.Generation
		}
		return nil
	})
	if err != nil {
		wipe()
		return nil, err
	}
	return out, nil
}

// bindUnmarkedSent is MarkSent for a sent message whose mls_mark_sent never
// ran: the process died after POST /:id/messages succeeded and before it. The
// server's row for it comes back in a display batch as a message from this
// device, and is bound here, in memory, if its bytes are exactly those of an
// outbox entry whose sealed copy is still unbound. The caller's single write
// carries the bind, so a batch refused later binds nothing.
//
// Byte equality with our own outbox is enough, and no more than that is being
// trusted. The outbox holds the exact ciphertext Send built under the lock,
// sealed in the same write as the copy of its plaintext. An MLS
// PrivateMessage carries a fresh nonce and our leaf's signature, so no other
// message has those bytes, and the server cannot make one match without
// having received them from us — which makes the row the message the copy is
// of. What the server still chooses is the seq, as it does for mls_mark_sent,
// which takes the seq from the POST response: showing the message at the seq
// the server numbers it with is what the explicit bind does too.
//
// A copy already bound to another seq is left alone: rebinding would make a
// re-read of that seq answer with a different message.
func (s *Store) bindUnmarkedSent(conversationID string, rec *Record, req ReceiveRequest) (ReceiveResult, bool, error) {
	var clientMessageID string
	for _, e := range rec.Outbox {
		if bytes.Equal(e.Ciphertext, req.Message) {
			clientMessageID = e.ClientMessageID
			break
		}
	}
	if clientMessageID == "" {
		return ReceiveResult{}, false, nil
	}
	i, ok := rec.findSentHistory(clientMessageID)
	if !ok || rec.History[i].Seq != 0 {
		return ReceiveResult{}, false, nil
	}
	rec.History[i].Seq = req.Seq
	out, err := s.reread(conversationID, rec, rec.History[i])
	if err != nil {
		return ReceiveResult{}, false, err
	}
	return out, true, nil
}

// forkDetected is a handshake for an epoch this device confirmed whose Commit
// is not the one it applied there. Receive turns it into the fork latch.
type forkDetected struct{ epoch uint64 }

func (e *forkDetected) Error() string {
	return "chat state was served another commit for an epoch it already confirmed"
}

// ErrNotApplication — a message in a display batch was a handshake. Commits
// go through the handshake path, in epoch order; nothing was written.
var ErrNotApplication = errors.New("chat state was handed a handshake as an application message")

// receiveOne is one delivery against a loaded record, in memory. It reports
// whether it changed the record; the caller writes it. The returned plaintext
// is a copy the caller owns.
func (s *Store) receiveOne(
	conversationID string, rec *Record, wm ServerWatermark, req ReceiveRequest,
	cipher ReceiveCipher, accept func([]byte) error,
) (ReceiveResult, bool, error) {
	if len(req.Message) == 0 {
		return ReceiveResult{}, false, errors.New("receive needs a message")
	}
	if stored, ok := rec.findHistory(req.Seq); ok && !req.Handshake {
		out, err := s.reread(conversationID, rec, stored)
		return out, false, err
	}
	// Opened here before and no copy left: the key was consumed at that
	// delivery, and handing the ciphertext to MLS again can only fail.
	if !req.Handshake && rec.opened(req.Seq, s.HistoryPolicy) {
		return ReceiveResult{}, false, errOpenedWithoutCopy
	}
	if !req.Handshake && rec.beforeJoin(req.FramedEpoch) {
		return ReceiveResult{}, false, errBeforeJoin
	}
	// A handshake for an epoch already confirmed here touches no MLS state,
	// so it is judged before anything that would refuse to feed MLS a new
	// message: a redelivery is ErrHandshakeApplied, and a different Commit
	// for an epoch the fork ring holds is a fork (Q16).
	if req.Handshake && len(rec.GroupState) > 0 && req.ProducedEpoch <= rec.Epoch {
		if rec.forkAt(req.ProducedEpoch, req.Message) {
			return ReceiveResult{}, false, &forkDetected{epoch: req.ProducedEpoch}
		}
		return ReceiveResult{}, false, ErrHandshakeApplied
	}
	// A re-read above is served from the sealed copy and never reaches
	// here, so an unsettled Commit does not stop anyone from reading what
	// they already have. What it does stop is feeding a new message to
	// MLS. A Commit handed to Open while ours is pending would be applied
	// by the library and would silently drop our pending along with it,
	// settling the race behind the record's back; ConfirmCommit is where
	// that message belongs (§7.3.2).
	if rec.Pending != nil {
		return ReceiveResult{}, false, ErrCommitPending
	}
	if len(rec.GroupState) == 0 {
		return ReceiveResult{}, false, ErrNoGroupState
	}
	if req.Handshake {
		switch {
		case req.ProducedEpoch <= rec.Epoch:
			return ReceiveResult{}, false, ErrHandshakeApplied
		case req.ProducedEpoch > rec.Epoch+1:
			return ReceiveResult{}, false, ErrHandshakeSkipped
		}
	}
	if err := cipher.Load(rec.GroupState); err != nil {
		return ReceiveResult{}, false, err
	}
	s.armAuthority(cipher, req.CommitMembers)

	opened, err := cipher.Open(req.Message)
	if err != nil {
		return ReceiveResult{}, false, err
	}
	defer secure.Zeroize(opened.Plaintext)
	if req.Handshake {
		if opened.Application {
			return ReceiveResult{}, false, ErrNotHandshake
		}
		// A device the Commit removed is left with no group to read an
		// epoch from, so only a Commit it survived is held to the claim.
		if !opened.Removed && opened.Epoch != req.ProducedEpoch {
			return ReceiveResult{}, false, ErrEpochStale
		}
	}

	position := Position{
		Epoch:           opened.Epoch,
		SenderLeafIndex: opened.SenderLeafIndex,
		ContentType:     ContentTypeApplication,
	}
	if opened.Application {
		if opened.KeyGeneration != nil {
			position.Generation = uint64(*opened.KeyGeneration)
		}
		if err := verifyDeclaration(
			opened.AuthenticatedData, position, opened.KeyGeneration,
		); err != nil {
			return ReceiveResult{}, false, err
		}
		if accept != nil {
			if err := accept(opened.Plaintext); err != nil {
				return ReceiveResult{}, false, err
			}
		}
	}

	// Judged on the state Open left behind: somebody else's Commit that
	// took the leaf out is confirmed the moment it is applied. A device
	// that was itself removed has no group left to read a roster from and
	// will never encrypt in it again, so its latch is left as it was.
	latch := storedLatches(rec)
	if !opened.Removed {
		if latch, err = judgeLatches(rec, wm, cipher); err != nil {
			return ReceiveResult{}, false, err
		}
	}

	state, err := cipher.State()
	if err != nil {
		return ReceiveResult{}, false, err
	}
	sender := Sender{AccountID: opened.SenderAccountID, DeviceID: opened.SenderDeviceID}
	first := true
	var entry HistoryEntry
	if opened.Application {
		if entry, err = s.sealHistory(conversationID, req.Seq, position, sender, opened.Plaintext, time.Now()); err != nil {
			return ReceiveResult{}, false, err
		}
	}
	rec.GroupState = state
	latch.apply(rec)
	rec.enterEpoch(opened.Epoch)
	if req.Handshake {
		rec.noteConfirmed(req.ProducedEpoch, req.Message)
	}
	rec.markOpened(req.Seq, s.HistoryPolicy)
	if opened.Removed {
		rec.RemovedFromGroup = true
	}
	if opened.Application {
		first = !rec.receivedContains(position)
		if first {
			rec.appendReceived(position)
		}
		rec.appendHistory(entry, s.HistoryPolicy, time.Now())
	}

	out := ReceiveResult{
		Application:   opened.Application,
		Removed:       opened.Removed,
		Position:      position,
		FirstDelivery: first,
		Generation:    rec.Generation,
	}
	if opened.Application {
		out.Plaintext = append([]byte(nil), opened.Plaintext...)
		out.Sender = sender
	}
	return out, true, nil
}

// ReadHistory answers a re-read without touching MLS at all. Receive does the
// same thing when it is handed a sequence it already has; this is the call for
// a caller that has no ciphertext to offer, which is the ordinary case for
// scrolling back. It answers on a conversation latched NeedsRekey too.
func (s *Store) ReadHistory(
	conversationID string, wm ServerWatermark, seq uint64,
) (ReceiveResult, error) {
	var out ReceiveResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
		if errors.Is(err, ErrRekeyRequired) {
			rec, err = s.loadLatched(p, conversationID)
		}
		if err != nil {
			return err
		}
		stored, ok := rec.findHistory(seq)
		if !ok {
			return ErrHistoryUnavailable
		}
		out, err = s.reread(conversationID, rec, stored)
		return err
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	return out, nil
}

// loadLatched reads the record of a conversation latched NeedsRekey, for a
// history re-read and for nothing else. The recovery from the latch is a new
// conversation, so this one stays read-only on this device, and its history is
// what remains readable of it.
//
// Serving it without the rollback judgement is safe because a re-read encrypts
// nothing, consumes no position and advances no MLS state: the latch exists to
// stop a rewound record from reusing a (key, nonce) or re-deriving a consumed
// key, and a re-read reaches neither. Every history entry is sealed under this
// owner's history key with its seq, position and sender bound into the AAD
// (history.go), so a rewound copy can only offer entries this device itself
// sealed at their first delivery. What it can do is bring back an entry that
// the current copy had since evicted from its ring. That is accepted: the
// entry is genuine, and the same holds for any backup of the file.
//
// Nothing is written, so the latch stays set, and nothing here can clear it.
// A file that is missing entirely has no history to offer.
func (s *Store) loadLatched(p convPaths, conversationID string) (*Record, error) {
	rec, err := s.readRecord(p, conversationID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, ErrRekeyRequired
	}
	return rec, nil
}

func (s *Store) reread(conversationID string, rec *Record, stored HistoryEntry) (ReceiveResult, error) {
	plaintext, position, err := s.openHistory(conversationID, stored)
	if err != nil {
		return ReceiveResult{}, err
	}
	return ReceiveResult{
		Plaintext:   plaintext,
		Application: true,
		Position:    position,
		Sender:      Sender{AccountID: stored.SenderAccountID, DeviceID: stored.SenderDeviceID},
		FromHistory: true,
		Generation:  rec.Generation,
	}, nil
}
