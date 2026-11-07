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

// The key purpose fixes the operation; member authority cannot authorize handoff.
func archiveRewrapCommitments(req proto.ArchiveUnwrapAndRewrapRequest) (groupRewrapContext, string, []proto.RewrapRecipientCommitment, error) {
	invalid := errors.New("invalid archive member regrant")
	if req.Validate() != nil || req.GrantContext == nil || req.OwnerAccountID == "" || (req.RecipientAccountID == "" && req.ArchiveRecipientAccountID == "") || req.OrgID != req.GrantContext.OrgID {
		return groupRewrapContext{}, "", nil, invalid
	}
	operation, domain, recipient := "archive_member_regrant", "dragpass:archive-member-regrant-request:v1", req.RecipientAccountID
	if req.ArchiveRecipientAccountID != "" {
		operation, domain, recipient = "archive_handoff", "dragpass:archive-handoff-request:v1", req.ArchiveRecipientAccountID
	}
	source, err := base64.StdEncoding.DecodeString(req.WrappedForArchiveB64)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	fp, err := crypto.RewrapKeyFingerprint(req.RecipientPublicKey)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	recipients := []proto.RewrapRecipientCommitment{{Kind: "account", AccountID: recipient, KeyFingerprint: fp}}
	text, err := proto.RewrapRecipientsDigest(recipients)
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	req.Decision = nil
	raw, err := json.Marshal(struct {
		Domain  string                              `json:"domain"`
		Request proto.ArchiveUnwrapAndRewrapRequest `json:"request"`
	}{domain, req})
	if err != nil {
		return groupRewrapContext{}, "", nil, invalid
	}
	c := groupRewrapContext{operation: operation, sourceKind: "stored_archive", orgID: req.OrgID, groupID: req.GrantContext.GroupID, dekVersion: req.GrantContext.DekVersion, sourcePolicy: req.GrantContext.Policy, outputPolicy: req.GrantContext.Policy, sourceDigest: sha256.Sum256(source), requestDigest: sha256.Sum256(raw)}
	decoded, _ := hex.DecodeString(text)
	copy(c.recipientsDigest[:], decoded)
	return c, text, recipients, nil
}
