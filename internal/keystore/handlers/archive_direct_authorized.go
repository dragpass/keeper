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

// Direct member regrant cannot authorize archive rotation or ownership handoff.
func archiveRewrapCommitments(req proto.ArchiveUnwrapAndRewrapRequest) (groupRewrapContext, string, []proto.RewrapRecipientCommitment, error) {
	invalid := errors.New("invalid archive member regrant")
	if req.Validate() != nil || req.GrantContext == nil || req.OwnerAccountID == "" || req.RecipientAccountID == "" || req.OrgID != req.GrantContext.OrgID {
		return groupRewrapContext{}, "", nil, invalid
	}
	source, err := base64.StdEncoding.DecodeString(req.WrappedForArchiveB64)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	fp, err := crypto.RewrapKeyFingerprint(req.RecipientPublicKey)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	recipients := []proto.RewrapRecipientCommitment{{Kind: "account", AccountID: req.RecipientAccountID, KeyFingerprint: fp}}
	text, err := proto.RewrapRecipientsDigest(recipients)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	req.Decision = nil
	raw, err := json.Marshal(struct {
		Domain  string                              `json:"domain"`
		Request proto.ArchiveUnwrapAndRewrapRequest `json:"request"`
	}{"dragpass:archive-member-regrant-request:v1", req})
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	c := groupRewrapContext{operation: "archive_member_regrant", sourceKind: "stored_archive", orgID: req.OrgID, groupID: req.GrantContext.GroupID, dekVersion: req.GrantContext.DekVersion, sourcePolicy: req.GrantContext.Policy, outputPolicy: req.GrantContext.Policy, sourceDigest: sha256.Sum256(source), requestDigest: sha256.Sum256(raw)}
	decoded, _ := hex.DecodeString(text)
	copy(c.recipientsDigest[:], decoded)
	return c, text, recipients, nil
}
