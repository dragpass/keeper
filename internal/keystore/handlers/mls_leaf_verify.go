// mls_leaf_verify.go — design §5.3 for every leaf that enters this device's
// view of an MLS group: the Go half of "Go verifies, Rust enforces".
//
// The mls package asks a LeafVerifier about the leaves a Commit, a Welcome or
// an Add would bring in, and hands the Rust gate exactly the ones that passed.
// This file is that verifier. For each leaf, in the order §5.3 gives:
//
//  1. read (account_id, device_id) from the credential identity
//  2. take the declaration from the leaf's extension; none, or a malformed
//     one, is a refusal
//  3. check the account key the extension carries against the pin: none →
//     TOFU from the carried key, same → keep, a chain the existing evaluator
//     accepts → rotated, anything else → changed
//  4. changed stops everything
//  5. verify the declaration's signature with that key (VerifyLeafDeclaration)
//  6. the declaration's account and device equal the credential's
//  7. the declaration's fingerprint equals the leaf's actual signature key
//
// and then the freshness checks. On entering leaves: the declaration's
// not_after has not passed, and, across the batch, no declaration is older
// than the newest this owner has accepted for its account (the
// superseded-declaration check, below). A leaf a Welcome's tree already holds
// is not entering: it gets steps 1–7, no expiry check, and a superseded
// declaration only once the grace period since this owner first saw the newer
// one has passed. It never moves the record. That is what keeps a group older
// than a declaration's 30-day window joinable.
//
// All or nothing: one bad leaf and VerifyLeaves fails, and nothing it would
// have recorded is kept. Even a success records nothing on its own — the pins
// and newest-declaration records it would write are held until the caller has
// seen the whole operation succeed and calls Commit. A Commit that adds one good
// and one bad leaf therefore writes no pin for the good one either.
//
// The pin state machine is not redefined here: evaluatePeerKeyTrust and
// verifyRotationChain are the ones the wrap actions use. The device's strict
// policy (applyPeerKeyPolicy) is not applied — see the Open items of the L2
// PR; nothing here wraps a key.

package handlers

import (
	"errors"
	"sort"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/mls"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// MLSLeafUntrustedError is a §5.3 refusal. Reason names the condition and
// never a value, because it travels into logs and error messages. The two
// fingerprints are set only when the pin reported the account key as changed,
// which is the one refusal the UI can offer a way through (§5.5's three paths).
type MLSLeafUntrustedError struct {
	Reason              string
	ObservedFingerprint string
	PinnedFingerprint   string
}

func (e *MLSLeafUntrustedError) Error() string { return "mls leaf untrusted: " + e.Reason }

func (e *MLSLeafUntrustedError) Unwrap() error { return mls.ErrLeafUntrusted }

func untrusted(reason string) error { return &MLSLeafUntrustedError{Reason: reason} }

// MLSLeafVerifier judges leaves for one owner's view of its peers. Use one per
// operation: Commit writes what the last successful VerifyLeaves staged.
type MLSLeafVerifier struct {
	d     Deps
	owner string

	// statements carries the rotation chains the caller has for an account
	// whose pinned key differs from the one its leaf carries (§12.2's
	// rotation_statements). A leaf extension has no room for them.
	statements map[string][]proto.KeyRotationStatement

	pins   map[string]keychain.PeerKeyPin
	newest map[string]keychain.MLSLeafNewest
}

var _ mls.LeafVerifier = (*MLSLeafVerifier)(nil)

func NewMLSLeafVerifier(
	d Deps, ownerAccountID string, statements map[string][]proto.KeyRotationStatement,
) *MLSLeafVerifier {
	return &MLSLeafVerifier{d: d, owner: ownerAccountID, statements: statements}
}

// judgedLeaf is what one leaf contributed once steps 1–7 passed.
type judgedLeaf struct {
	accountID   string
	notBefore   int64
	notAfter    int64
	fingerprint string
	entering    bool
}

// VerifyLeaves runs §5.3 over every leaf, then the newest-declaration check
// over the batch, and stages what a success would record.
func (v *MLSLeafVerifier) VerifyLeaves(leaves []mls.Leaf) error {
	v.pins, v.newest = nil, nil

	if resp, ok := requirePeerKeyOwner(v.d, v.owner); !ok {
		return errors.New(resp.Error)
	}

	pins := map[string]keychain.PeerKeyPin{}
	judged := make([]judgedLeaf, 0, len(leaves))
	now := v.d.Now().Unix()

	for _, leaf := range leaves {
		j, err := v.judge(leaf, pins, now)
		if err == nil && j.entering && now >= j.notAfter {
			err = untrusted("leaf declaration has expired")
		}
		if err != nil {
			v.d.Logger.Printf("mls leaf verify refused a leaf: %v", err)
			return err
		}
		judged = append(judged, j)
	}

	newest, err := v.checkNewest(judged, now)
	if err != nil {
		v.d.Logger.Printf("mls leaf verify refused a leaf: %v", err)
		return err
	}

	v.pins, v.newest = pins, newest
	return nil
}

func (v *MLSLeafVerifier) judge(
	leaf mls.Leaf, pins map[string]keychain.PeerKeyPin, now int64,
) (judgedLeaf, error) {
	// 1.
	accountID, deviceID, err := mls.ParseCredentialIdentity(leaf.Identity)
	if err != nil {
		return judgedLeaf{}, untrusted("leaf credential is not a dragpass device identity")
	}

	// 2.
	if leaf.Declaration == nil {
		return judgedLeaf{}, untrusted("leaf carries no leaf declaration")
	}
	ext, err := decodeMLSLeafExtension(leaf.Declaration)
	if err != nil {
		return judgedLeaf{}, untrusted("leaf declaration extension is malformed")
	}
	accountKey, err := crypto.ParsePublicKey(ext.AccountPublicKey)
	if err != nil {
		return judgedLeaf{}, untrusted("leaf declaration carries an unreadable account key")
	}
	observed := crypto.AccountKeyFingerprint([]byte(ext.AccountPublicKey))

	// 3–4.
	if accountID == v.owner {
		// This owner's own devices are judged against the key this Keeper
		// holds, not against a pin: there is no pin for oneself, and the local
		// key is a better answer than any first observation.
		own, err := keychain.GetPublicKey(v.d.Store)
		if err != nil || own == "" {
			return judgedLeaf{}, errors.New("mls leaf verify: this device's account public key is not readable")
		}
		if crypto.AccountKeyFingerprint([]byte(own)) != observed {
			return judgedLeaf{}, &MLSLeafUntrustedError{
				Reason:              "leaf claims this account but carries a different account key",
				ObservedFingerprint: observed,
				PinnedFingerprint:   crypto.AccountKeyFingerprint([]byte(own)),
			}
		}
	} else {
		existing, err := v.pinFor(accountID, pins)
		if err != nil {
			return judgedLeaf{}, err
		}
		outcome := evaluatePeerKeyTrust(existing, accountID, observed, v.statements[accountID], now)
		if !outcome.Allowed {
			return judgedLeaf{}, &MLSLeafUntrustedError{
				Reason:              "peer account key changed: " + outcome.Reason,
				ObservedFingerprint: observed,
				PinnedFingerprint:   outcome.PinnedFingerprint,
			}
		}
		pins[accountID] = outcome.Pin
	}

	// 5.
	decl := ext.Declaration
	if err := VerifyLeafDeclaration(decl, accountKey); err != nil {
		return judgedLeaf{}, untrusted(err.Error())
	}

	// 6.
	if decl.AccountID != accountID || decl.DeviceID != deviceID {
		return judgedLeaf{}, untrusted("leaf declaration names a different account or device than the credential")
	}

	// 7.
	fingerprint, err := crypto.MLSLeafSignatureKeyFingerprint(leaf.SignatureKey)
	if err != nil || fingerprint != decl.SignatureKeyFingerprint {
		return judgedLeaf{}, untrusted("leaf declaration vouches for a different signature key")
	}

	return judgedLeaf{
		accountID: accountID, notBefore: decl.NotBefore, notAfter: decl.NotAfter,
		fingerprint: fingerprint, entering: leaf.Entering,
	}, nil
}

// pinFor reads a pin, preferring one an earlier leaf of this batch staged, so
// two leaves of one account are judged against the same answer.
func (v *MLSLeafVerifier) pinFor(accountID string, staged map[string]keychain.PeerKeyPin) (*keychain.PeerKeyPin, error) {
	if pin, ok := staged[accountID]; ok {
		return &pin, nil
	}
	pin, err := loadPeerKeyPin(v.d.Store, v.owner, accountID)
	if err != nil {
		return nil, errors.New("mls leaf verify: failed to read peer key pin")
	}
	return pin, nil
}

// checkNewest refuses a superseded declaration: on an entering leaf always, on
// a leaf a Welcome's tree already holds once the grace period has passed.
//
// A declaration embedded in a leaf is never checked against the directory, so
// one the account has since replaced still verifies. What a device can do on
// its own is remember the newest declaration it has accepted for each account
// and refuse anything older. It is order-independent within a batch: the
// newest candidate is the latest of the stored record and every entering
// declaration in the batch, and every entering declaration for the account
// must be that one. Equal not_before with a different key is refused too — two
// keys cannot both be current.
//
// Only entering leaves advance the record; letting a tree leaf move it could
// move it backwards. A tree leaf is held to the record more loosely: a member
// who has just rotated still sits in its older groups under the old leaf until
// it replaces that leaf there with an Update Commit, so an older declaration in
// a tree is accepted for MLSLeafTreeGraceSeconds after this owner first saw the
// newer one, and refused after. A tree leaf newer than the record is not
// refused either: it was judged by the members when it entered, and this
// device simply has not caught up.
//
// What it cannot do is protect a device that never saw the newer declaration:
// that device accepts the stale one, at the Add and in a tree alike.
func (v *MLSLeafVerifier) checkNewest(judged []judgedLeaf, now int64) (map[string]keychain.MLSLeafNewest, error) {
	byAccount := map[string][]judgedLeaf{}
	for _, j := range judged {
		byAccount[j.accountID] = append(byAccount[j.accountID], j)
	}
	advanced := map[string]keychain.MLSLeafNewest{}
	for accountID, js := range byAccount {
		stored, found, err := keychain.GetMLSLeafNewest(v.d.Store, v.owner, accountID)
		if err != nil {
			return nil, errors.New("mls leaf verify: failed to read the newest leaf declaration record")
		}
		// A record 0.0.44–0.0.47 wrote has no first_seen_at. Taking it as seen
		// now starts the grace period on upgrade instead of refusing at once:
		// the rule did not exist when the rotation was seen, so nobody has had
		// the window to move their groups to the new leaf yet. The value is
		// written back on success, so the clock starts once and not on every read.
		backfilled := found && stored.FirstSeenAt == 0
		if backfilled {
			stored.FirstSeenAt = now
		}
		top, have := stored, found
		for _, j := range js {
			if j.entering && (!have || j.notBefore > top.NotBefore) {
				top = keychain.MLSLeafNewest{NotBefore: j.notBefore, Fingerprint: j.fingerprint, FirstSeenAt: now}
				have = true
			}
		}
		for _, j := range js {
			if !j.entering {
				continue
			}
			if j.notBefore < top.NotBefore {
				return nil, untrusted("leaf declaration is older than one already accepted for its account")
			}
			if j.fingerprint != top.Fingerprint {
				return nil, untrusted("two leaf declarations with the same not_before name different keys")
			}
		}
		if have && now-top.FirstSeenAt > proto.MLSLeafTreeGraceSeconds {
			for _, j := range js {
				if !j.entering && supersededBy(j, top) {
					return nil, untrusted("leaf in the tree carries a declaration superseded longer than the grace period ago")
				}
			}
		}
		if have && (!found || backfilled || !top.SameDeclaration(stored)) {
			advanced[accountID] = top
		}
	}
	return advanced, nil
}

// supersededBy is the record's notion of older: an earlier not_before, or the
// same not_before with a different key.
func supersededBy(j judgedLeaf, rec keychain.MLSLeafNewest) bool {
	return j.notBefore < rec.NotBefore || (j.notBefore == rec.NotBefore && j.fingerprint != rec.Fingerprint)
}

// Commit writes what the last successful VerifyLeaves staged: first-use and
// refreshed pins, and newest-declaration records that moved forward or had
// their first_seen_at filled in from a version 1 record. Call it
// only after the operation the verification was for has fully succeeded —
// chatstate's write included. A crash between that write and this one leaves
// the group state ahead of the pins, which costs a repeated first-use on the
// next observation of the same key, not an acceptance of a different one.
func (v *MLSLeafVerifier) Commit() error {
	for _, accountID := range sortedKeys(v.pins) {
		if err := keychain.SavePeerKeyPin(v.d.Store, v.owner, accountID, v.pins[accountID]); err != nil {
			return errors.New("mls leaf verify: failed to save peer key pin")
		}
	}
	for _, accountID := range sortedKeys(v.newest) {
		if err := keychain.SaveMLSLeafNewest(v.d.Store, v.owner, accountID, v.newest[accountID]); err != nil {
			return errors.New("mls leaf verify: failed to save the newest leaf declaration record")
		}
	}
	v.pins, v.newest = nil, nil
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeMLSLeafExtension is the one place the extension payload is parsed:
// bounded before parsing, then decoded with no unknown, duplicate or missing
// key at any depth, then validated.
func decodeMLSLeafExtension(payload []byte) (proto.MLSLeafExtension, error) {
	if len(payload) == 0 || len(payload) > proto.MLSLeafExtensionMaxBytes {
		return proto.MLSLeafExtension{}, errors.New("leaf declaration extension is empty or too large")
	}
	var ext proto.MLSLeafExtension
	if err := strictDecodeJSON(payload, &ext); err != nil {
		return proto.MLSLeafExtension{}, err
	}
	if err := ext.Validate(); err != nil {
		return proto.MLSLeafExtension{}, err
	}
	return ext, nil
}
