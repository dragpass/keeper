// succession.go — when one account's leaf may take another leaf's place in a
// group (design §0.3 policy 1, Q1, Q2).
//
// # The rule
//
// A Commit that removes a leaf of account A and adds a leaf of A under another
// signature key hands A's seat to a different device. That is a succession,
// and it is allowed only when the old leaf approved it:
//
//	H   a handover statement naming the removed leaf (device and key) and the
//	    added leaf (device and key), signed with the removed leaf's own
//	    signature key, rides in the Commit's authenticated data. The removed
//	    leaf is the one in the tree the Commit was applied to, so the key it is
//	    checked against is the authenticated group's, never one a server hands
//	    out.
//
// A server login token alone never satisfies it: it does not hold the old
// leaf's key. A device that has the account key (from a password) but not the
// old device still needs the old device's approval.
//
// A leaf of A re-added under the same signature key it had is a re-seat (a
// rejoin), not a succession, and is not judged here.
//
// # Time
//
// A handover is valid for at most HandoverMaxSeconds between issued_at and
// expires_at, and the old device refuses to sign one for a request that has
// expired. Nobody checks expires_at against the clock afterwards: a member
// that was offline for a week still has to be able to build or apply the
// replacement. What a late use can do is only the succession the old leaf
// approved, for that exact old leaf and that exact new leaf.

package chatstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	// LeafHandoverDomain keeps a handover signature from verifying as any
	// other statement the same leaf key could be made to sign. MLS's own
	// signatures carry the "MLS 1.0 " label prefix, so none of them starts
	// with this.
	LeafHandoverDomain  = "dragpass.mls.leaf.handover"
	LeafHandoverVersion = 1

	// HandoverMaxSeconds is the request window design Q1 fixed: ten minutes.
	HandoverMaxSeconds = 600

	// maxHandoverBytes bounds the authenticated data before it is parsed.
	maxHandoverBytes = 16384
	maxHandovers     = 32
)

// LeafHandover is the old leaf's approval of one succession.
type LeafHandover struct {
	AccountID      string
	OldDeviceID    string
	OldFingerprint string
	NewDeviceID    string
	NewFingerprint string
	IssuedAt       int64
	ExpiresAt      int64
	Signature      []byte
}

// LeafHandoverCanonical renders the signing string.
//
//	dragpass.mls.leaf.handover|1|<account_id>|<old_device_id>|<old_fp>|<new_device_id>|<new_fp>|<issued_at>|<expires_at>
func LeafHandoverCanonical(h LeafHandover) string {
	return strings.Join([]string{
		LeafHandoverDomain,
		strconv.Itoa(LeafHandoverVersion),
		h.AccountID,
		h.OldDeviceID,
		h.OldFingerprint,
		h.NewDeviceID,
		h.NewFingerprint,
		strconv.FormatInt(h.IssuedAt, 10),
		strconv.FormatInt(h.ExpiresAt, 10),
	}, "|")
}

var (
	lowerUUID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrHandoverInvalid — a handover is malformed, names another succession than
// the one it is offered for, or its signature does not verify under the old
// leaf's key.
var ErrHandoverInvalid = errors.New("chat state leaf handover is not valid for this succession")

// Validate checks the statement's shape and window, not its signature.
func (h LeafHandover) Validate() error {
	for _, id := range []string{h.AccountID, h.OldDeviceID, h.NewDeviceID} {
		if !lowerUUID.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return ErrHandoverInvalid
		}
	}
	if !lowerHex64.MatchString(h.OldFingerprint) || !lowerHex64.MatchString(h.NewFingerprint) {
		return ErrHandoverInvalid
	}
	if h.OldDeviceID == h.NewDeviceID || h.OldFingerprint == h.NewFingerprint {
		return ErrHandoverInvalid
	}
	if h.IssuedAt <= 0 || h.ExpiresAt < h.IssuedAt || h.ExpiresAt-h.IssuedAt > HandoverMaxSeconds {
		return ErrHandoverInvalid
	}
	if len(h.Signature) != ed25519.SignatureSize {
		return ErrHandoverInvalid
	}
	return nil
}

// VerifyUnder checks the signature under the old leaf's raw Ed25519 key and
// that the key is the one the statement names.
func (h LeafHandover) VerifyUnder(oldKey []byte) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if len(oldKey) != ed25519.PublicKeySize || leafKeyFingerprint(oldKey) != h.OldFingerprint {
		return ErrHandoverInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(oldKey), []byte(LeafHandoverCanonical(h)), h.Signature) {
		return ErrHandoverInvalid
	}
	return nil
}

func leafKeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// ─── the authenticated data a replace Commit carries ────────────────────────

type handoverWire struct {
	AccountID      string `json:"account_id"`
	OldDeviceID    string `json:"old_device_id"`
	OldFingerprint string `json:"old_signature_key_fingerprint"`
	NewDeviceID    string `json:"new_device_id"`
	NewFingerprint string `json:"new_signature_key_fingerprint"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	Signature      string `json:"signature"`
}

type handoverEnvelope struct {
	V         int            `json:"v"`
	Handovers []handoverWire `json:"handovers"`
}

// EncodeHandovers is the authenticated data of a Commit that carries these
// handovers. Nil for none, so a Commit without one carries no data at all.
func EncodeHandovers(hs []LeafHandover) ([]byte, error) {
	if len(hs) == 0 {
		return nil, nil
	}
	env := handoverEnvelope{V: 1, Handovers: make([]handoverWire, len(hs))}
	for i, h := range hs {
		env.Handovers[i] = handoverWire{
			AccountID: h.AccountID, OldDeviceID: h.OldDeviceID, OldFingerprint: h.OldFingerprint,
			NewDeviceID: h.NewDeviceID, NewFingerprint: h.NewFingerprint,
			IssuedAt: h.IssuedAt, ExpiresAt: h.ExpiresAt,
			Signature: base64.StdEncoding.EncodeToString(h.Signature),
		}
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(out) > maxHandoverBytes {
		return nil, ErrHandoverInvalid
	}
	return out, nil
}

// DecodeHandovers reads a received Commit's authenticated data. Empty is no
// handover. Anything else must be exactly an envelope EncodeHandovers could
// have written: a Commit carrying data this device cannot read is refused
// rather than read as carrying nothing.
func DecodeHandovers(data []byte) ([]LeafHandover, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) > maxHandoverBytes {
		return nil, ErrHandoverInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env handoverEnvelope
	if err := dec.Decode(&env); err != nil || dec.More() {
		return nil, ErrHandoverInvalid
	}
	if env.V != 1 || len(env.Handovers) == 0 || len(env.Handovers) > maxHandovers {
		return nil, ErrHandoverInvalid
	}
	out := make([]LeafHandover, len(env.Handovers))
	for i, w := range env.Handovers {
		sig, err := base64.StdEncoding.DecodeString(w.Signature)
		if err != nil {
			return nil, ErrHandoverInvalid
		}
		out[i] = LeafHandover{
			AccountID: w.AccountID, OldDeviceID: w.OldDeviceID, OldFingerprint: w.OldFingerprint,
			NewDeviceID: w.NewDeviceID, NewFingerprint: w.NewFingerprint,
			IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt, Signature: sig,
		}
		if err := out[i].Validate(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ─── the judgement ──────────────────────────────────────────────────────────

// SuccessionLeaf is one leaf as the rule needs it. AccountKey is the
// fingerprint of the account key its declaration carries; empty when the
// declaration could not be read, which never counts as a changed key.
type SuccessionLeaf struct {
	AccountID    string
	DeviceID     string
	SignatureKey []byte
	AccountKey   string
}

// Fingerprint is the leaf signature key's fingerprint.
func (l SuccessionLeaf) Fingerprint() string { return leafKeyFingerprint(l.SignatureKey) }

// SuccessionChange is one Commit, built here or received: who commits it,
// which leaves of the tree before it it removes, what it adds, and the
// handovers it carries.
type SuccessionChange struct {
	CommitterAccountID string
	Removed            []SuccessionLeaf
	Added              []SuccessionLeaf
	Handovers          []LeafHandover
}

// JudgeSuccession holds a Commit to the rule above. Nil means allowed.
func JudgeSuccession(c SuccessionChange) error {
	refuse := func(reason string) error {
		return &UnauthorizedCommitError{CommitterAccountID: c.CommitterAccountID, Reason: reason}
	}
	for _, added := range c.Added {
		var removedOfAccount []SuccessionLeaf
		for _, r := range c.Removed {
			if r.AccountID == added.AccountID {
				removedOfAccount = append(removedOfAccount, r)
			}
		}
		if len(removedOfAccount) == 0 {
			continue // a plain Add, judged by the authority rules
		}
		if slices.ContainsFunc(removedOfAccount, func(r SuccessionLeaf) bool {
			return bytes.Equal(r.SignatureKey, added.SignatureKey)
		}) {
			continue // a re-seat of the same leaf key
		}
		if approvedByOldLeaf(c.Handovers, removedOfAccount, added) {
			continue // H
		}
		return refuse("a leaf of an account replaces another of its leaves without the old leaf's handover")
	}
	return nil
}

func approvedByOldLeaf(handovers []LeafHandover, removed []SuccessionLeaf, added SuccessionLeaf) bool {
	for _, h := range handovers {
		if h.AccountID != added.AccountID || h.NewDeviceID != added.DeviceID || h.NewFingerprint != added.Fingerprint() {
			continue
		}
		for _, r := range removed {
			if h.OldDeviceID == r.DeviceID && h.VerifyUnder(r.SignatureKey) == nil {
				return true
			}
		}
	}
	return false
}
