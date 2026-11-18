// archive_session_slot.go — the per-organization recovery-session private
// key slot, its record format and how far Keeper trusts what it holds.
//
// Each organization's slot (config.OrgArchiveSessionPrivateKeyPrefix +
// org_id, with the public half under config.OrgArchiveSessionPublicKeyPrefix
// + org_id) carries its own expiry so that a session the App never ends (a
// crash, a closed tab, a lost network) cannot leave a usable session key
// behind: every use reads the expiry first, refuses an expired slot and
// deletes it. Nothing here depends on the App or the server telling Keeper
// that the session ended. Every function takes the organization it acts on
// and touches no other organization's slot.
//
// Record format (one keyring value, written in one Set):
//
//	dragpass-archive-session-v2 expires_at=<unix> begun_at=<unix> fp=<hex> begin_id=<uuid or ->\n<private key PEM>
//
// fp is the session public key's fingerprint (hex(sha256(public key PEM))),
// the value begin returned; begin_id is the caller's idempotency value, "-"
// when the begin carried none. Neither is secret. The expiry is the earlier
// of begin time + archiveSessionMaxTTL and the server's expires_at the App
// reports through archive_session_set_expiry, which can only move it
// earlier.
//
// Trust. A slot is judged as one of:
//
//   - absent: no private record (a public half left alone by an interrupted
//     write or delete is no key);
//   - live / expired: a v2 record this Keeper can read whose fp matches the
//     public half and whose expiry is no further ahead than any session this
//     Keeper starts; only these are ever deleted for being expired;
//   - expiry unknown: a v2 record whose expiry lies beyond that bound (a
//     clock moved back);
//   - unowned: anything else, among them the per-organization records of
//     development builds before this format (the v1 header, no header) and
//     a v2 record whose halves disagree.
//
// An expiry-unknown or unowned slot is never used, replaced or deleted by
// begin, set_expiry, end, a combine or a sweep. Only the confirmed
// archive_session_discard naming its fingerprint removes it.
//
// The device-wide slot of Keepers before lv90 is not a session slot here: it
// is never read, indexed, swept or ended, whatever it holds. Only the
// confirmed archive_session_legacy_discard deletes it.
//
// Every read-check-delete and every write of a slot, the session index and
// the device-wide slot runs under the keychain process lock (in-process
// mutex plus a cross-process file lock on the platform keyring), so a Keeper
// process that starts while the App service begins a session cannot delete
// the new session on the strength of an earlier read. RSA key generation
// stays outside the lock.

package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"github.com/dragpass/keeper/internal/keystore/crypto"
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

const archiveSessionSlotHeader = "dragpass-archive-session-v2 "

var (
	errArchiveSessionExpired       = errors.New("archive session key expired")
	errArchiveSessionExpiryUnknown = errors.New("archive session key has no usable expiry")
	// errArchiveSessionDeleteFailed: a slot could not be deleted completely.
	// It answers storage_failure.
	errArchiveSessionDeleteFailed = errors.New("archive session slot delete failed")
)

// archiveSessionRecord is the header of a v2 slot record.
type archiveSessionRecord struct {
	expiresAt   time.Time
	begunAt     time.Time
	fingerprint string
	beginID     string // "" when the begin carried none
}

// encodeArchiveSessionSlot returns the record for pem in a locked buffer.
// The caller destroys it after the Set.
func encodeArchiveSessionSlot(rec archiveSessionRecord, pem []byte) *memguard.LockedBuffer {
	beginID := rec.beginID
	if beginID == "" {
		beginID = "-"
	}
	header := archiveSessionSlotHeader +
		"expires_at=" + strconv.FormatInt(rec.expiresAt.Unix(), 10) +
		" begun_at=" + strconv.FormatInt(rec.begunAt.Unix(), 10) +
		" fp=" + rec.fingerprint +
		" begin_id=" + beginID + "\n"
	value := make([]byte, 0, len(header)+len(pem))
	value = append(value, header...)
	value = append(value, pem...)
	return memguard.NewBufferFromBytes(value)
}

// decodeArchiveSessionSlot splits a v2 record. ok is false for anything
// else, including the v1 header of development builds.
func decodeArchiveSessionSlot(value string) (rec archiveSessionRecord, pem string, ok bool) {
	rest, found := strings.CutPrefix(value, archiveSessionSlotHeader)
	if !found {
		return archiveSessionRecord{}, "", false
	}
	line, pem, found := strings.Cut(rest, "\n")
	if !found || pem == "" {
		return archiveSessionRecord{}, "", false
	}
	fields := strings.Split(line, " ")
	if len(fields) != 4 {
		return archiveSessionRecord{}, "", false
	}
	values := make([]string, 4)
	for i, name := range []string{"expires_at=", "begun_at=", "fp=", "begin_id="} {
		v, found := strings.CutPrefix(fields[i], name)
		if !found {
			return archiveSessionRecord{}, "", false
		}
		values[i] = v
	}
	expires, ok := parseCanonicalUnix(values[0])
	if !ok {
		return archiveSessionRecord{}, "", false
	}
	begun, ok := parseCanonicalUnix(values[1])
	if !ok {
		return archiveSessionRecord{}, "", false
	}
	if !isLowerHex64(values[2]) {
		return archiveSessionRecord{}, "", false
	}
	beginID := values[3]
	if beginID == "-" {
		beginID = ""
	} else if !isLowerUUID(beginID) {
		return archiveSessionRecord{}, "", false
	}
	return archiveSessionRecord{
		expiresAt: time.Unix(expires, 0), begunAt: time.Unix(begun, 0),
		fingerprint: values[2], beginID: beginID,
	}, pem, true
}

// parseCanonicalUnix reads a positive decimal number exactly as
// strconv.FormatInt writes it (no sign, no leading zero), the only way
// Keeper writes one.
func parseCanonicalUnix(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || strconv.FormatInt(v, 10) != s {
		return 0, false
	}
	return v, true
}

func isLowerHex64(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func isLowerUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// archiveSessionProcessLock is the keychain process lock every session slot,
// index and device-wide slot access runs under. A variable only so tests can
// observe which accesses hold it, as archiveSlotProcessLock is.
var archiveSessionProcessLock = keychain.WithKeychainProcessLock

// withArchiveSessionSlotLock runs fn under the keychain process lock. fn
// must not take the lock again.
func withArchiveSessionSlotLock(d Deps, fn func() error) error {
	return archiveSessionProcessLock(d.Store, fn)
}

type archiveSessionSlotState int

const (
	archiveSessionSlotAbsent archiveSessionSlotState = iota
	archiveSessionSlotLive
	archiveSessionSlotExpired
	archiveSessionSlotExpiryUnknown
	archiveSessionSlotUnowned
)

// trusted reports whether the slot's record and expiry are Keeper's own: only
// such a slot is ever used or deleted for being expired.
func (s archiveSessionSlotState) trusted() bool {
	return s == archiveSessionSlotLive || s == archiveSessionSlotExpired
}

// archiveSessionSlot is one read of an organization's slot, taken under the
// lock. It carries no private key material.
type archiveSessionSlot struct {
	state archiveSessionSlotState
	// record is set for live, expired and expiry-unknown slots.
	record archiveSessionRecord
	// fingerprint is the slot's key fingerprint: the public half's when it
	// is there, else the v2 record's, else the one derived from a parsable
	// private key; "" when none exists.
	fingerprint string
	// storedDigest is hex(sha256(private record)), set only when the slot
	// has no fingerprint at all (a private record that is not a parsable
	// key, with no public half and no v2 record). It is not a key
	// fingerprint; it lets the confirmed discard name that slot.
	storedDigest string
	// publicKey is the public half ("" when missing).
	publicKey string
	// digest is sha256 of the private record as read.
	digest [sha256.Size]byte
}

// inspectArchiveSessionSlotLocked reads orgID's slot and judges it. It
// writes nothing. The caller holds the lock. When pem is not nil and the
// slot is live, the private key PEM is handed to it before the read value
// is wiped.
func inspectArchiveSessionSlotLocked(d Deps, orgID string, pem func(string)) (archiveSessionSlot, error) {
	value, err := keychain.GetArchiveSessionPrivateKey(d.Store, orgID)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return archiveSessionSlot{}, err
	}
	defer secure.WipeString(&value)
	if value == "" {
		return archiveSessionSlot{state: archiveSessionSlotAbsent}, nil
	}
	public, err := keychain.GetArchiveSessionPublicKey(d.Store, orgID)
	if err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return archiveSessionSlot{}, err
	}
	slot := archiveSessionSlot{state: archiveSessionSlotUnowned, publicKey: public, digest: sha256.Sum256([]byte(value))}
	if public != "" {
		slot.fingerprint = fingerprintBase64Public(public)
	}
	rec, recordPEM, ok := decodeArchiveSessionSlot(value)
	if !ok {
		if public == "" {
			deriveArchiveSessionFingerprint(&slot, value)
		}
		return slot, nil
	}
	if public == "" {
		slot.fingerprint = rec.fingerprint
		return slot, nil
	}
	if subtle.ConstantTimeCompare([]byte(slot.fingerprint), []byte(rec.fingerprint)) != 1 {
		return slot, nil
	}
	slot.record = rec
	now := d.Now()
	switch {
	case !archiveSessionRecordConsistent(rec, now):
		slot.state = archiveSessionSlotExpiryUnknown
	case !now.Before(rec.expiresAt):
		slot.state = archiveSessionSlotExpired
	default:
		slot.state = archiveSessionSlotLive
		if pem != nil {
			pem(recordPEM)
		}
	}
	return slot, nil
}

// deriveArchiveSessionFingerprint names an unowned slot that has neither a
// public half nor a v2 record: the fingerprint of the private key's public
// key in begin's encoding (PKIX "PUBLIC KEY" PEM), or, when the record is
// not a parsable key, the digest of the stored bytes. Only this shape has
// its private key parsed outside a combine; the PEM is held in a locked
// buffer as the combine holds it, never logged or returned, and nothing is
// written.
func deriveArchiveSessionFingerprint(slot *archiveSessionSlot, value string) {
	start := strings.Index(value, "-----BEGIN")
	if start >= 0 {
		buf := memguard.NewBufferFromBytes([]byte(value[start:]))
		priv, err := crypto.ParsePrivateKey(string(buf.Bytes()))
		buf.Destroy()
		if err == nil {
			if der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey); err == nil {
				public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
				slot.fingerprint = fingerprintBase64Public(string(public))
				return
			}
		}
	}
	digest := sha256.Sum256([]byte(value))
	slot.storedDigest = hex.EncodeToString(digest[:])
}

// archiveSessionRecordConsistent reports whether rec's times are ones this
// Keeper could have written and kept: begin no later than now, an expiry no
// earlier than the begin (set_expiry deletes rather than store a passed
// time) and within archiveSessionMaxTTL of the begin and of now. Keeper
// writes begun_at from its own clock, so a later begin means the clock moved
// back; there is no skew allowance, the same as the expiry bound, which
// already refuses any backward step past begin + 30 minutes. A record
// failing any of these is never used or deleted for being expired.
func archiveSessionRecordConsistent(rec archiveSessionRecord, now time.Time) bool {
	return !rec.begunAt.After(now) &&
		!rec.expiresAt.Before(rec.begunAt) &&
		!rec.expiresAt.After(rec.begunAt.Add(archiveSessionMaxTTL)) &&
		!rec.expiresAt.After(now.Add(archiveSessionMaxTTL))
}

// openArchiveSessionSlot reads the session private key for a combine. Under
// the lock it returns keychain.ErrSecretNotFound when no session is open,
// errArchiveSessionExpired after deleting an expired slot, and
// errArchiveSessionExpiryUnknown (slot kept) for an expiry-unknown or
// unowned slot. On success the caller destroys the buffer.
func openArchiveSessionSlot(d Deps, orgID string) (*memguard.LockedBuffer, archiveSessionSlot, error) {
	var buf *memguard.LockedBuffer
	var read archiveSessionSlot
	err := withArchiveSessionSlotLock(d, func() error {
		slot, err := inspectArchiveSessionSlotLocked(d, orgID, func(pem string) {
			buf = memguard.NewBufferFromBytes([]byte(pem))
		})
		if err != nil {
			return err
		}
		return useArchiveSessionSlotForCombineLocked(d, orgID, slot, func() { read = slot })
	})
	if err != nil {
		if buf != nil {
			buf.Destroy()
		}
		return nil, archiveSessionSlot{}, err
	}
	return buf, read, nil
}

// recheckArchiveSessionSlotForOutput judges orgID's slot again, under the
// lock, right before a combine that read it as read lets its output out.
// The same record (same digest), still trusted and not expired now, passes.
// Otherwise: no slot, or another key in it (a discard and a new begin), is
// keychain.ErrSecretNotFound and the slot is not touched; the same record
// is judged by the use rule (expired: deleted, errArchiveSessionExpired, or
// errArchiveSessionDeleteFailed; untrusted now: kept,
// errArchiveSessionExpiryUnknown). A lock that cannot be taken is an error
// too.
func recheckArchiveSessionSlotForOutput(d Deps, orgID string, read archiveSessionSlot) error {
	return withArchiveSessionSlotLock(d, func() error {
		slot, err := inspectArchiveSessionSlotLocked(d, orgID, nil)
		if err != nil {
			return err
		}
		if slot.state != archiveSessionSlotAbsent && subtle.ConstantTimeCompare(slot.digest[:], read.digest[:]) != 1 {
			return keychain.ErrSecretNotFound
		}
		return useArchiveSessionSlotForCombineLocked(d, orgID, slot, func() {})
	})
}

// useArchiveSessionSlotForCombineLocked is the combine's judgement of a slot
// read under the lock, at its open and right before its output. It is the
// one place the combine's slot check lives: the account boundary change adds
// the comparison with the server decision's account here, for both reads.
func useArchiveSessionSlotForCombineLocked(d Deps, orgID string, slot archiveSessionSlot, live func()) error {
	return useArchiveSessionSlotLocked(d, orgID, slot, live)
}

// useArchiveSessionSlotLocked applies the use rule to a slot just read: no
// session is not_found, an expired one is deleted, an untrusted one is
// refused and kept. live runs for a live slot. The caller holds the lock.
func useArchiveSessionSlotLocked(d Deps, orgID string, slot archiveSessionSlot, live func()) error {
	switch slot.state {
	case archiveSessionSlotAbsent:
		return keychain.ErrSecretNotFound
	case archiveSessionSlotExpired:
		if err := deleteArchiveSessionSlot(d, orgID); err != nil {
			return err
		}
		return errArchiveSessionExpired
	case archiveSessionSlotLive:
		live()
		return nil
	default:
		return errArchiveSessionExpiryUnknown
	}
}

// deleteArchiveSessionSlot removes orgID's session keypair and its index
// entry. The caller holds the lock. The key halves are deleted all or
// reported: the private half goes first and a failure of either half stops
// it (errArchiveSessionDeleteFailed):
//
//   - the private half fails: nothing was touched, the slot keeps its
//     classification (a trusted slot stays usable, endable and sweepable)
//     and the next attempt deletes it;
//   - the public half fails: no private key is left, only a public half and
//     the index entry, which read as an absent slot and are removed by the
//     next sweep.
//
// No single failure leaves a private key that nothing will remove. An
// already missing half counts as deleted. The index entry is removed last
// and a failure there is not reported: the key is gone, an index Keeper
// cannot read is never rewritten here, and a sweep drops an entry whose
// slot holds no private record.
func deleteArchiveSessionSlot(d Deps, orgID string) error {
	if err := keychain.DeleteArchiveSessionPrivateKey(d.Store, orgID); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errArchiveSessionDeleteFailed
	}
	if err := keychain.DeleteArchiveSessionPublicKey(d.Store, orgID); err != nil && !errors.Is(err, keychain.ErrSecretNotFound) {
		return errArchiveSessionDeleteFailed
	}
	_ = keychain.RemoveArchiveSessionOrg(d.Store, orgID)
	return nil
}

// archiveSessionSlotResponse maps openArchiveSessionSlot errors to the wire.
func archiveSessionSlotResponse(err error) proto.BaseResponse {
	switch {
	case errors.Is(err, errArchiveSessionExpired):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionExpired, "archive session key expired")
	case errors.Is(err, errArchiveSessionExpiryUnknown):
		return errs.CodeResponse(errs.ErrCodeArchiveSessionExpiryUnknown, "archive session key has no usable expiry")
	case errors.Is(err, errArchiveSessionDeleteFailed):
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "delete archive session slot failed")
	case errors.Is(err, keychain.ErrSecretNotFound):
		return errs.Response(err) // not_found
	default:
		return errs.CodeResponse(errs.ErrCodeStorageFailure, "read archive session slot failed")
	}
}

// archiveSessionFingerprintMatches reports whether orgID's slot holds the
// key whose fingerprint begin returned.
func archiveSessionFingerprintMatches(d Deps, orgID, fingerprint string) bool {
	public, err := keychain.GetArchiveSessionPublicKey(d.Store, orgID)
	if err != nil || public == "" {
		return false
	}
	return fingerprintBase64Public(public) == fingerprint
}
