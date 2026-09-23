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
	"errors"
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

// ErrHistoryUnavailable — the sealed copy for this sequence is not there, or
// cannot say who sent it. A re-read of a message whose history has been
// evicted, expired or damaged ends here, and it is terminal: the MLS key for it was consumed and deleted when it
// was first delivered, so the server's ciphertext cannot stand in.
var ErrHistoryUnavailable = errors.New("chat state has no local copy of that message")

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
		if err != nil || !changed {
			return err
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
// On a conversation latched NeedsRekey a batch made only of re-reads is still
// answered, from the history and without MLS (loadLatched). A batch holding
// even one sequence the history does not have is refused whole with
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
