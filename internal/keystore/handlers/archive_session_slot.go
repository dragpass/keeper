// archive_session_slot.go — the recovery-session private key slot and its
// expiry.
//
// The slot carries its own expiry so that a session the App never ends (a
// crash, a closed tab, a lost network) cannot leave a usable session key
// behind: every use reads the expiry first, refuses an expired slot and
// deletes it. Nothing here depends on the App or the server telling Keeper
// that the session ended.
//
// Record format (one keyring value, written in one Set):
//
//	dragpass-archive-session-v1 expires_at=<unix seconds>\n<private key PEM>
//
// The expiry is the earlier of begin time + archiveSessionMaxTTL and the
// server's expires_at the App reports through archive_session_set_expiry,
// which can only move it earlier. A missing or forged server value therefore
// never keeps the key past the Keeper-side bound.
//
// A value without the header was written by a Keeper before lv100 F1 and
// has no known expiry. It is refused for use (archive_session_expiry_unknown)
// and never deleted by a use, by the startup sweep or by
// archive_session_end: lv90 (keeper #206) leaves its deletion to the user's
// confirmed discard. By user decision (2026-11-17), until #206 merges a new
// archive_session_begin keeps replacing it as before; after #206 begin is
// refused while it exists, until the confirmed discard. A header Keeper cannot parse, or an expiry
// further ahead than any session this Keeper starts (a clock moved back), is
// refused the same way: its expiry is not trusted, so it is not deleted by
// an expiry rule either.
//
// Every read-check-delete and every write of the slot runs under the
// keychain process lock (in-process mutex plus a cross-process file lock on
// the platform keyring), so a Keeper process that starts while the App
// service begins a session cannot delete the new session on the strength of
// an earlier read. RSA key generation stays outside the lock.

package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/secure"
)

// archiveSessionMaxTTL bounds every session slot from its begin. The server
// session lives 30 minutes from its open (ariadne archiveQuorumSessionTTL),
// and the open follows begin, so the same 30 minutes counted from begin ends
// the slot no later than the server session even when the App never reports
// the server's expires_at. The cost is that the slot may end up to the
// begin-to-open gap before the server session does.
const archiveSessionMaxTTL = 30 * time.Minute

const archiveSessionSlotHeader = "dragpass-archive-session-v1 expires_at="

var (
	errArchiveSessionExpired       = errors.New("archive session key expired")
	errArchiveSessionExpiryUnknown = errors.New("archive session key has no usable expiry")
)

// encodeArchiveSessionSlot returns the record for pem with expiresAt in a
// locked buffer. The caller destroys it after the Set.
func encodeArchiveSessionSlot(expiresAt time.Time, pem []byte) *memguard.LockedBuffer {
	header := archiveSessionSlotHeader + strconv.FormatInt(expiresAt.Unix(), 10) + "\n"
	value := make([]byte, 0, len(header)+len(pem))
	value = append(value, header...)
	value = append(value, pem...)
	return memguard.NewBufferFromBytes(value)
}

// decodeArchiveSessionSlot splits a record. ok is false for a value without
// a well-formed header.
func decodeArchiveSessionSlot(value string) (expiresAt time.Time, pem string, ok bool) {
	rest, found := strings.CutPrefix(value, archiveSessionSlotHeader)
	if !found {
		return time.Time{}, "", false
	}
	digits, pem, found := strings.Cut(rest, "\n")
	if !found || pem == "" {
		return time.Time{}, "", false
	}
	unix, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || unix <= 0 {
		return time.Time{}, "", false
	}
	return time.Unix(unix, 0), pem, true
}

// withArchiveSessionSlotLock runs fn under the keychain process lock. fn
// must not take the lock again.
func withArchiveSessionSlotLock(d Deps, fn func() error) error {
	return keychain.WithKeychainProcessLock(d.Store, fn)
}

// archiveSessionSlot is one read of the slot, taken under the lock.
type archiveSessionSlot struct {
	expiresAt time.Time
	digest    [sha256.Size]byte
}

// readArchiveSessionSlotLocked reads the slot for a use and hands its PEM to
// use. Under the caller's lock it returns keychain.ErrSecretNotFound when no
// session is open, errArchiveSessionExpired after deleting an expired slot,
// and errArchiveSessionExpiryUnknown (slot kept) when the expiry cannot be
// trusted. The PEM string is wiped when use returns.
func readArchiveSessionSlotLocked(d Deps, use func(slot archiveSessionSlot, pem string) error) error {
	value, err := keychain.GetArchiveSessionPrivateKey(d.Store)
	if err != nil {
		return err
	}
	defer secure.WipeString(&value)
	if value == "" {
		return keychain.ErrSecretNotFound
	}
	expiresAt, pem, ok := decodeArchiveSessionSlot(value)
	now := d.Now()
	if !ok || expiresAt.After(now.Add(archiveSessionMaxTTL)) {
		return errArchiveSessionExpiryUnknown
	}
	if !now.Before(expiresAt) {
		deleteArchiveSessionSlot(d)
		return errArchiveSessionExpired
	}
	return use(archiveSessionSlot{expiresAt: expiresAt, digest: sha256.Sum256([]byte(value))}, pem)
}

// openArchiveSessionSlot reads the session private key for a use (see
// readArchiveSessionSlotLocked for the errors). On success the caller
// destroys the buffer.
func openArchiveSessionSlot(d Deps) (*memguard.LockedBuffer, archiveSessionSlot, error) {
	var buf *memguard.LockedBuffer
	var read archiveSessionSlot
	err := withArchiveSessionSlotLock(d, func() error {
		return readArchiveSessionSlotLocked(d, func(slot archiveSessionSlot, pem string) error {
			buf = memguard.NewBufferFromBytes([]byte(pem))
			read = slot
			return nil
		})
	})
	if err != nil {
		return nil, archiveSessionSlot{}, err
	}
	return buf, read, nil
}

// deleteArchiveSessionSlotIfUnchanged deletes the slot only while it still
// holds the value read earlier, so a session begun since then is kept.
func deleteArchiveSessionSlotIfUnchanged(d Deps, read archiveSessionSlot) {
	_ = withArchiveSessionSlotLock(d, func() error {
		value, err := keychain.GetArchiveSessionPrivateKey(d.Store)
		current := sha256.Sum256([]byte(value))
		secure.WipeString(&value)
		if err == nil && subtle.ConstantTimeCompare(current[:], read.digest[:]) == 1 {
			deleteArchiveSessionSlot(d)
		}
		return nil
	})
}

// deleteArchiveSessionSlot removes both halves of the session keypair. The
// caller holds the lock. Failures are ignored as in archive_session_end: the
// private half is deleted first, and an expired slot left behind by a failed
// delete is refused again at its next use.
func deleteArchiveSessionSlot(d Deps) {
	_ = keychain.DeleteArchiveSessionPrivateKey(d.Store)
	_ = keychain.DeleteArchiveSessionPublicKey(d.Store)
}

// archiveSessionSlotResponse maps openArchiveSessionSlot errors to the wire.
func archiveSessionSlotResponse(err error) proto.BaseResponse {
	switch {
	case errors.Is(err, errArchiveSessionExpired):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionExpired, "archive session key expired")
	case errors.Is(err, errArchiveSessionExpiryUnknown):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionExpiryUnknown, "archive session key has no usable expiry")
	default:
		return errs.Response(err) // not_found if no session is open
	}
}

// archiveSessionFingerprintMatches reports whether the stored session public
// key has fingerprint, as archive_session_begin returned it.
func archiveSessionFingerprintMatches(d Deps, fingerprint string) bool {
	public, err := keychain.GetArchiveSessionPublicKey(d.Store)
	if err != nil || public == "" {
		return false
	}
	return fingerprintBase64Public(public) == fingerprint
}
