// Package mls links the MLS (RFC 9420) implementation Keeper uses and keeps
// the serialized group state it produces inside the existing chat state record.
//
// # What is here and what is not
//
// This is the skeleton: the library is linked, its policy is fixed, and the
// bytes it serializes reach disk through chatstate's whole-file replacement.
// The send and receive ordering that has to sit on top of it — naming the
// generation before consuming it, burning an uncertain one after a crash,
// holding the lock across the encryption — is not here yet.
//
// # Build tag
//
// The binding needs cgo and a Rust static library, so it sits behind the `mls`
// build tag and a stub answers ErrUnavailable without it. The default build is
// byte-for-byte what it was: the Linux release still builds with CGO_ENABLED=0
// and still ships a static binary, which linking this would end. Keeping the
// tag off by default is what lets the library be measured and reviewed before
// that trade is made rather than as a side effect of making it.
//
// # Memory
//
// mls-rs protects key material with zeroize, which overwrites a buffer when the
// value holding it is dropped. That is the whole of the protection: it does not
// reach copies made along the way, the allocation a growing Vec abandons, pages
// the OS wrote to swap, or a core dump. The Rust side allocates from a plain
// global heap, so Keeper's memguard arena does not cover any of it. Secrets in
// this package's Go buffers are not covered either unless the caller wipes them.
package mls

import (
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
)

// ErrUnavailable — this binary was built without the MLS library. Distinct from
// every other failure so a caller never reads "no group" when the real answer is
// "no library".
var ErrUnavailable = errors.New("mls: this build does not include the MLS library")

// WireForm is the framing a message actually went out in, read back off the
// encoded bytes. Asserting on this rather than on the setting that produced it
// is what would catch an upstream default changing under us.
type WireForm uint8

const (
	WireFormOther WireForm = iota
	WireFormPublicMessage
	WireFormPrivateMessage
	WireFormWelcome
	WireFormKeyPackage
	WireFormGroupInfo
)

func (w WireForm) String() string {
	switch w {
	case WireFormPublicMessage:
		return "PublicMessage"
	case WireFormPrivateMessage:
		return "PrivateMessage"
	case WireFormWelcome:
		return "Welcome"
	case WireFormKeyPackage:
		return "KeyPackage"
	case WireFormGroupInfo:
		return "GroupInfo"
	default:
		return "other"
	}
}

// Processed is the outcome of applying one inbound message. Plaintext is set
// only for an application message and is the caller's to wipe.
type Processed struct {
	Epoch       uint64
	Removed     bool
	Application bool
	Plaintext   []byte
}

// Persist flushes the session's group state into the conversation's record.
//
// The flush and the write are two steps because only the second is durable.
// mls-rs advances its secret tree in memory and writes nothing until it is
// asked, so anything that moved the group forward is lost unless this runs
// after it. Pairing an advance with this call is an invariant of the layer
// above; nothing below checks it.
func Persist(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (uint64, error) {
	blob, err := s.Flush()
	if err != nil {
		return 0, err
	}
	return store.SaveGroupState(conversationID, wm, blob)
}

// Restore loads the conversation's stored group state into the session. It
// reports false when the conversation has no group state yet, which is an
// ordinary state and not an error.
func Restore(
	store *chatstate.Store,
	conversationID string,
	wm chatstate.ServerWatermark,
	s *Session,
) (bool, error) {
	blob, err := store.LoadGroupState(conversationID, wm)
	if err != nil {
		return false, err
	}
	if len(blob) == 0 {
		return false, nil
	}
	return true, s.Load(blob)
}
