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
// confirmed discard. Until that action exists, a new archive_session_begin
// still replaces it as before. A header Keeper cannot parse, or an expiry
// further ahead than any session this Keeper starts (a clock moved back), is
// refused the same way: its expiry is not trusted, so it is not deleted by
// an expiry rule either.

package handlers

import (
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
// which follows begin; the 5 extra minutes cover the time between the two.
const archiveSessionMaxTTL = 35 * time.Minute

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

// openArchiveSessionSlot reads the session private key for a use. It returns
// keychain.ErrSecretNotFound when no session is open,
// errArchiveSessionExpired after deleting an expired slot, and
// errArchiveSessionExpiryUnknown (slot kept) when the expiry cannot be
// trusted. On success the caller destroys the buffer.
func openArchiveSessionSlot(d Deps) (*memguard.LockedBuffer, time.Time, error) {
	value, err := keychain.GetArchiveSessionPrivateKey(d.Store)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer secure.WipeString(&value)
	if value == "" {
		return nil, time.Time{}, keychain.ErrSecretNotFound
	}
	expiresAt, pem, ok := decodeArchiveSessionSlot(value)
	now := d.Now()
	if !ok || expiresAt.After(now.Add(archiveSessionMaxTTL)) {
		return nil, time.Time{}, errArchiveSessionExpiryUnknown
	}
	if !now.Before(expiresAt) {
		deleteArchiveSessionSlot(d)
		return nil, time.Time{}, errArchiveSessionExpired
	}
	return memguard.NewBufferFromBytes([]byte(pem)), expiresAt, nil
}

// deleteArchiveSessionSlot removes both halves of the session keypair.
// Failures are ignored as in archive_session_end: the private half is
// deleted first, and an expired slot left behind by a failed delete is
// refused again at its next use.
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
