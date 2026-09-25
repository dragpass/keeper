// succession.go — the Go half of the succession rule (chatstate/succession.go):
// read leaves as the rule needs them, check the handovers a replace this
// device builds carries, and judge every received Commit.

package mls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
)

// successionLeaf names a leaf by account, device, signature key and the
// account key its declaration carries. The declaration is read for that one
// field only: every leaf reaching here was verified in full by the leaf
// verifier, as it entered or in this very operation, so its declaration is
// already known good. A leaf whose declaration does not read carries no
// account key, which the rule never takes for a changed one.
func successionLeaf(l Leaf) (chatstate.SuccessionLeaf, error) {
	account, device, err := ParseCredentialIdentity(l.Identity)
	if err != nil {
		return chatstate.SuccessionLeaf{}, err
	}
	out := chatstate.SuccessionLeaf{AccountID: account, DeviceID: device, SignatureKey: l.SignatureKey}
	var ext struct {
		AccountPublicKey string `json:"account_public_key"`
	}
	if len(l.Declaration) > 0 && json.Unmarshal(l.Declaration, &ext) == nil && ext.AccountPublicKey != "" {
		out.AccountKey = crypto.AccountKeyFingerprint([]byte(ext.AccountPublicKey))
	}
	return out, nil
}

func successionLeaves(leaves []Leaf) ([]chatstate.SuccessionLeaf, error) {
	out := make([]chatstate.SuccessionLeaf, 0, len(leaves))
	for _, l := range leaves {
		s, err := successionLeaf(l)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// committerOf is the account of the leaf at index in before.
func committerOf(before []Leaf, index uint32) (string, error) {
	for _, l := range before {
		if l.Index == index {
			account, _, err := ParseCredentialIdentity(l.Identity)
			return account, err
		}
	}
	return "", failed("the committer is not a leaf of the group")
}

// judgeSuccession holds a Commit to the succession rule. added carries each
// entering leaf (a KeyPackage's, or an Add the collect pass saw).
func judgeSuccession(
	removed, added []Leaf, committer string, handovers []chatstate.LeafHandover, roles *chatstate.Roles,
	building, userInitiated bool,
) error {
	r, err := successionLeaves(removed)
	if err != nil {
		return err
	}
	a, err := successionLeaves(added)
	if err != nil {
		return err
	}
	return chatstate.JudgeSuccession(chatstate.SuccessionChange{
		CommitterAccountID: committer,
		Removed:            r,
		Added:              a,
		Handovers:          handovers,
		Building:           building,
		UserInitiated:      userInitiated,
		Roles:              roles,
	})
}

// judgeReceivedSuccession is the receiving half: the handovers are whatever
// the committer put in the Commit's authenticated data, and data that does
// not read as handovers is a refusal, as is a succession none of them covers.
func judgeReceivedSuccession(shape CommitShape, change chatstate.CommitChange) error {
	handovers, err := chatstate.DecodeHandovers(shape.AuthenticatedData)
	if err != nil {
		return &chatstate.UnauthorizedCommitError{
			CommitterAccountID: change.CommitterAccountID,
			CommitterDeviceID:  change.CommitterDeviceID,
			Reason:             "the commit carries authenticated data that is not a leaf handover",
		}
	}
	err = judgeSuccession(shape.Removed, shape.Added, change.CommitterAccountID, handovers,
		change.EffectiveRoles(), false, false)
	var refused *chatstate.UnauthorizedCommitError
	if errors.As(err, &refused) {
		refused.CommitterDeviceID = change.CommitterDeviceID
	}
	return err
}

// checkHandover holds a handover the caller hands in for a replace this
// device builds to the leaves it is for: the account, the removed leaf's
// device and key (the signature verifies under that key), and the entering
// leaf's device and key. A handover that fails is refused as such, never
// quietly dropped, so a caller that meant to carry an approval learns it
// carried none.
func checkHandover(h chatstate.LeafHandover, removed []Leaf, entering Leaf) error {
	in, err := successionLeaf(entering)
	if err != nil {
		return err
	}
	if h.AccountID != in.AccountID || h.NewDeviceID != in.DeviceID || h.NewFingerprint != in.Fingerprint() {
		return fmt.Errorf("%w: it names another new leaf than the key package's", chatstate.ErrHandoverInvalid)
	}
	for _, l := range removed {
		out, err := successionLeaf(l)
		if err != nil {
			return err
		}
		if out.AccountID == h.AccountID && out.DeviceID == h.OldDeviceID && h.VerifyUnder(out.SignatureKey) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: it is not signed by the leaf the replace removes", chatstate.ErrHandoverInvalid)
}
