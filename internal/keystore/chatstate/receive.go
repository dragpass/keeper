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
}

// ReceiveRequest is one inbound message. Seq is the server's sequence, which
// is what a re-read asks by and what the local history is keyed on.
type ReceiveRequest struct {
	Seq     uint64
	Message []byte
}

// ReceiveResult is what the caller may show.
type ReceiveResult struct {
	Plaintext   []byte
	Application bool
	Removed     bool
	Position    Position

	// FirstDelivery is false when this position was already marked.
	FirstDelivery bool

	// FromHistory is true when the plaintext came out of the local sealed copy
	// and no MLS key was touched. A re-read is always this.
	FromHistory bool

	// Generation is the record's write counter after the confirmation, or the
	// current one when nothing was written.
	Generation uint64
}

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
		if stored, ok := rec.findHistory(req.Seq); ok {
			out, err = s.reread(conversationID, rec, stored)
			return err
		}
		// A re-read above is served from the sealed copy and never reaches
		// here, so an unsettled Commit does not stop anyone from reading what
		// they already have. What it does stop is feeding a new message to
		// MLS. A Commit handed to Open while ours is pending would be applied
		// by the library and would silently drop our pending along with it,
		// settling the race behind the record's back; ConfirmCommit is where
		// that message belongs (§7.3.2).
		if rec.Pending != nil {
			return ErrCommitPending
		}
		if len(rec.GroupState) == 0 {
			return ErrNoGroupState
		}
		if err := cipher.Load(rec.GroupState); err != nil {
			return err
		}

		opened, err := cipher.Open(req.Message)
		if err != nil {
			return err
		}
		defer secure.Zeroize(opened.Plaintext)

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
				return err
			}
		}

		state, err := cipher.State()
		if err != nil {
			return err
		}
		loaded := rec.Generation
		rec.GroupState = state
		rec.enterEpoch(opened.Epoch)
		first := true
		if opened.Application {
			first = !rec.receivedContains(position)
			if first {
				rec.appendReceived(position)
			}
			entry, err := s.sealHistory(conversationID, req.Seq, position, opened.Plaintext, time.Now())
			if err != nil {
				return err
			}
			rec.appendHistory(entry, s.HistoryPolicy, time.Now())
		}
		// One replacement carries the advanced state, the mark and the sealed
		// copy. There is no arrangement of these three that can be observed
		// half-done, which is what §8.4's first condition asks for.
		if err := s.commit(p, rec, loaded, anchor); err != nil {
			return err
		}

		out = ReceiveResult{
			Application:   opened.Application,
			Removed:       opened.Removed,
			Position:      position,
			FirstDelivery: first,
			Generation:    rec.Generation,
		}
		if opened.Application {
			out.Plaintext = append([]byte(nil), opened.Plaintext...)
		}
		return nil
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	return out, nil
}

// ReadHistory answers a re-read without touching MLS at all. Receive does the
// same thing when it is handed a sequence it already has; this is the call for
// a caller that has no ciphertext to offer, which is the ordinary case for
// scrolling back.
func (s *Store) ReadHistory(
	conversationID string, wm ServerWatermark, seq uint64,
) (ReceiveResult, error) {
	var out ReceiveResult
	err := s.withConversation(conversationID, func(p convPaths) error {
		rec, _, err := s.loadChecked(p, conversationID, wm)
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

func (s *Store) reread(conversationID string, rec *Record, stored HistoryEntry) (ReceiveResult, error) {
	plaintext, position, err := s.openHistory(conversationID, stored)
	if err != nil {
		return ReceiveResult{}, err
	}
	return ReceiveResult{
		Plaintext:   plaintext,
		Application: true,
		Position:    position,
		FromHistory: true,
		Generation:  rec.Generation,
	}, nil
}
