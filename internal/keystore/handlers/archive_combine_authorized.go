package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// The complete request binds the recovery session and every encrypted share,
// including fields that affect peer pin verification. No decision is hashed.
func combineRewrapCommitments(req proto.ArchiveQuorumCombineAndRewrapRequest) (groupRewrapContext, string, []proto.RewrapRecipientCommitment, error) {
	invalid := errors.New("invalid archive combine request")
	if req.Validate() != nil || req.GrantContext == nil || req.OwnerAccountID == "" || req.RecoverySessionID == "" {
		return groupRewrapContext{}, "", nil, invalid
	}
	source, err := base64.StdEncoding.DecodeString(req.WrappedOldDEKB64)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	recipients := make([]proto.RewrapRecipientCommitment, 0, len(req.Recipients))
	for _, r := range req.Recipients {
		if r.AccountID == "" || r.OrgArchive {
			return groupRewrapContext{}, "", nil, invalid
		}
		fp, err := crypto.RewrapKeyFingerprint(r.PublicKey)
		if err != nil {
			return groupRewrapContext{}, "", nil, invalid
		}
		recipients = append(recipients, proto.RewrapRecipientCommitment{Kind: "account", AccountID: r.AccountID, KeyFingerprint: fp})
	}
	text, err := proto.RewrapRecipientsDigest(recipients)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	req.Decision = nil
	raw, err := json.Marshal(struct {
		Domain  string                                     `json:"domain"`
		Request proto.ArchiveQuorumCombineAndRewrapRequest `json:"request"`
	}{"dragpass:archive-combine-request:v1", req})
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	c := groupRewrapContext{operation: "quorum_combine", sourceKind: "archive_quorum", orgID: req.GrantContext.OrgID, groupID: req.GrantContext.GroupID, dekVersion: req.GrantContext.DekVersion, sourcePolicy: req.GrantContext.Policy, outputPolicy: req.GrantContext.Policy, sourceDigest: sha256.Sum256(source), requestDigest: sha256.Sum256(raw)}
	decoded, _ := hex.DecodeString(text)
	copy(c.recipientsDigest[:], decoded)
	return c, text, recipients, nil
}
