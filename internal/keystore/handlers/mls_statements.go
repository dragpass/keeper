// mls_statements.go — the signed statements a Remove rests on (0.0.55, design
// Q5 (b), Q13), the actions that sign them, and the verifier every Commit's
// authenticated data is held to (chatstate.RemovalEvidence).
//
// Which key verifies what:
//
//   - A leave and a device revocation are the removed account's own word. They
//     verify under the account key in the removed leaf's own declaration, from
//     the authenticated tree: this device pinned that key when the leaf
//     entered (§5.3), so no key the server serves is consulted.
//   - An org removal is an org admin's word about somebody else. It verifies
//     under the key it carries, held to this device's pin for the admin
//     account: the same key as before, a rotation chain the evaluator
//     accepts, or the first key seen (TOFU, recorded). A changed key refuses.
//     That the account is an org admin at all is the server's claim; this
//     device cannot check it (stated in chatstate/authority.go).

package handlers

import (
	"encoding/json"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// statementEvidence is chatstate.RemovalEvidence for one owner's view of one
// conversation.
type statementEvidence struct {
	d              Deps
	owner          string
	orgID          string
	conversationID string
}

var _ chatstate.RemovalEvidence = statementEvidence{}

func newStatementEvidence(d Deps, permit proto.ChatStatePermit) statementEvidence {
	return statementEvidence{d: d, owner: permit.AccountID, orgID: permit.OrgID, conversationID: permit.ConversationID}
}

// NewStatementEvidence is the verifier the MLS actions set on every cipher
// (mls.Cipher.SetEvidence), for a caller that drives a cipher itself.
func NewStatementEvidence(d Deps, permit proto.ChatStatePermit) chatstate.RemovalEvidence {
	return newStatementEvidence(d, permit)
}

// Authorized reads the statements in change.AuthenticatedData and marks every
// removed leaf one of them covers. Data that is not the evidence layout
// carries no statement and counts as one invalid.
func (e statementEvidence) Authorized(change chatstate.CommitChange) ([]bool, int, error) {
	out := make([]bool, len(change.Removed))
	if len(change.AuthenticatedData) == 0 || len(change.RemovedLeaves) != len(change.Removed) {
		return out, 0, nil
	}
	ev, err := proto.DecodeMLSCommitEvidence(change.AuthenticatedData)
	if err != nil {
		return out, 1, nil
	}
	invalid := 0
	for _, s := range ev.OrgRemovals {
		if !e.orgRemovalVerifies(s) {
			invalid++
			continue
		}
		for i, account := range change.Removed {
			if account == s.RemovedAccountID {
				out[i] = true
			}
		}
	}
	for _, s := range ev.Leaves {
		ok, seen := e.ownStatementVerifies(change, s.AccountID, "", 0, s.Signature, proto.MLSLeaveCanonical(s))
		if seen && (!ok || s.ConversationID != e.conversationID || s.Validate("leave") != nil) {
			invalid++
			continue
		}
		if !ok {
			continue
		}
		for i, account := range change.Removed {
			if account == s.AccountID {
				out[i] = true
			}
		}
	}
	for _, s := range ev.DeviceRevocations {
		ok, seen := e.ownStatementVerifies(change, s.AccountID, s.DeviceID, s.RevokedAt, s.Signature,
			proto.MLSDeviceRevocationCanonical(s))
		if seen && (!ok || s.Validate("device_revocation") != nil) {
			invalid++
			continue
		}
		if !ok {
			continue
		}
		for i, leaf := range change.RemovedLeaves {
			if leaf.AccountID == s.AccountID && leaf.DeviceID == s.DeviceID {
				out[i] = true
			}
		}
	}
	return out, invalid, nil
}

// ownStatementVerifies checks an account's statement against the account key
// in the declaration of a leaf of that account the Commit removes. With a
// device, only that device's leaf counts, and the leaf must have been
// declared no later than the revocation: a device enrolled again after it was
// revoked is not removed by the old revocation. seen reports whether the
// Commit removes a leaf the statement could be checked against at all; a
// statement about nobody removed is unused, not invalid.
func (e statementEvidence) ownStatementVerifies(
	change chatstate.CommitChange, account, device string, notAfter int64, signature, canonical string,
) (ok, seen bool) {
	for _, leaf := range change.RemovedLeaves {
		if leaf.AccountID != account || (device != "" && leaf.DeviceID != device) {
			continue
		}
		seen = true
		ext, err := decodeMLSLeafExtension(leaf.Declaration)
		if err != nil {
			return false, true
		}
		if device != "" && ext.Declaration.NotBefore > notAfter {
			return false, true
		}
		if verifyStatementSignature([]byte(ext.AccountPublicKey), signature, canonical) != nil {
			return false, true
		}
		return true, true
	}
	return false, seen
}

// orgRemovalVerifies checks an org admin's statement: this conversation's
// organization, the signature under the key it carries, and that key against
// this owner's pin for the admin account (first use recorded).
func (e statementEvidence) orgRemovalVerifies(s proto.MLSOrgRemovalStatement) bool {
	if s.Validate("org_removal", true) != nil || s.OrgID != e.orgID {
		return false
	}
	if verifyStatementSignature([]byte(s.AdminPublicKey), s.Signature, proto.MLSOrgRemovalCanonical(s)) != nil {
		return false
	}
	return e.adminKeyTrusted(s.AdminAccountID, s.AdminPublicKey) == nil
}

func (e statementEvidence) adminKeyTrusted(admin, publicKeyPEM string) error {
	observed := crypto.AccountKeyFingerprint([]byte(publicKeyPEM))
	if admin == e.owner {
		own, err := keychain.GetPublicKey(e.d.Store)
		if err != nil || crypto.AccountKeyFingerprint([]byte(own)) != observed {
			return errors.New("the statement claims this account with another key")
		}
		return nil
	}
	if resp, ok := requirePeerKeyOwner(e.d, e.owner); !ok {
		return errors.New(resp.Error)
	}
	existing, err := loadPeerKeyPin(e.d.Store, e.owner, admin)
	if err != nil {
		return err
	}
	outcome := evaluatePeerKeyTrust(existing, admin, observed, nil, e.d.Now().Unix())
	if !outcome.Allowed {
		return errors.New("the admin's account key changed: " + outcome.Reason)
	}
	if existing == nil {
		if err := keychain.SavePeerKeyPin(e.d.Store, e.owner, admin, outcome.Pin); err != nil {
			return err
		}
	}
	return nil
}

// commitEvidence is the authenticated data a build carries, one document for
// both rules: the statements the request handed in and the handover of each
// replace entry, as they are. Validate has already bounded them; the
// judgement verifies the statements (ErrStatementUnverified) and the build
// the handovers, over these same bytes, as every receiver will.
func commitEvidence(req proto.MLSCommitBuildRequest) ([]byte, error) {
	ev := proto.MLSCommitEvidence{
		OrgRemovals:       req.OrgRemovalStatements,
		Leaves:            req.LeaveStatements,
		DeviceRevocations: req.DeviceRevocations,
	}
	for _, m := range req.Replace {
		if m.Handover != nil {
			ev.Handovers = append(ev.Handovers, *m.Handover)
		}
	}
	return ev.Encode()
}

// rolesPayload turns a wire role set into the group context payload.
func rolesPayload(set *proto.MLSRoleSet) ([]byte, error) {
	if set == nil {
		return nil, nil
	}
	entries := make([]chatstate.RoleEntry, len(set.Entries))
	for i, e := range set.Entries {
		entries[i] = chatstate.RoleEntry{AccountID: e.AccountID, Role: e.Role}
	}
	roles, err := chatstate.RolesFromEntries(set.Kind, entries)
	if err != nil {
		return nil, err
	}
	return roles.Encode(), nil
}

// HandleMLSLeaveRequestSign signs this device's request to leave a
// conversation (0.0.55, design Q13).
func HandleMLSLeaveRequestSign(d Deps, payload json.RawMessage) proto.BaseResponse {
	var req proto.MLSLeaveRequestSignRequest
	c, resp, ok := openMLSChat(d, payload, &req, proto.ChatStateMaxRequestBytes)
	if !ok {
		return resp
	}
	defer c.close()

	statement := proto.MLSLeaveStatement{
		ConversationID: c.conv,
		AccountID:      c.permit.AccountID,
		RequestedAt:    d.Now().Unix(),
	}
	sig, resp, ok := signWithAccountKey(d, proto.MLSLeaveCanonical(statement))
	if !ok {
		return resp
	}
	statement.Signature = sig
	d.Logger.Println("mls leave request sign successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSLeaveRequestSignResponseData{Statement: statement}}
}

// HandleOrgMemberRemovalSign signs this org admin's statement that an account
// was removed from the organization (0.0.55, design Q5 (b)). The admin
// account must be the one this device's active leaf belongs to.
func HandleOrgMemberRemovalSign(d Deps, req proto.OrgMemberRemovalSignRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if resp, ok := requireOwnAccount(d, req.AdminAccountID); !ok {
		return resp
	}
	statement := proto.MLSOrgRemovalStatement{
		OrgID:            req.OrgID,
		RemovedAccountID: req.RemovedAccountID,
		AdminAccountID:   req.AdminAccountID,
		RemovedAt:        d.Now().Unix(),
	}
	sig, resp, ok := signWithAccountKey(d, proto.MLSOrgRemovalCanonical(statement))
	if !ok {
		return resp
	}
	statement.Signature = sig
	d.Logger.Println("org member removal sign successful")
	return proto.BaseResponse{Success: true, Data: proto.OrgMemberRemovalSignResponseData{Statement: statement}}
}

// HandleMLSDeviceRevokeSign signs this account's revocation of one of its
// devices' leaves (0.0.55, design Q13).
func HandleMLSDeviceRevokeSign(d Deps, req proto.MLSDeviceRevokeSignRequest) proto.BaseResponse {
	if err := req.Validate(); err != nil {
		return errs.Response(err)
	}
	if resp, ok := requireOwnAccount(d, req.AccountID); !ok {
		return resp
	}
	statement := proto.MLSDeviceRevocation{
		AccountID: req.AccountID,
		DeviceID:  req.DeviceID,
		RevokedAt: d.Now().Unix(),
	}
	sig, resp, ok := signWithAccountKey(d, proto.MLSDeviceRevocationCanonical(statement))
	if !ok {
		return resp
	}
	statement.Signature = sig
	d.Logger.Println("mls device revoke sign successful")
	return proto.BaseResponse{Success: true, Data: proto.MLSDeviceRevokeSignResponseData{Statement: statement}}
}

// requireOwnAccount refuses a statement for an account other than the one
// this device's active leaf belongs to: the account key signs only in its own
// name.
func requireOwnAccount(d Deps, accountID string) (proto.BaseResponse, bool) {
	key, found, err := keychain.GetMLSLeafKey(d.Store)
	if err != nil || !found {
		return errs.CodeResponse(errs.ErrorCode(proto.ChatMLSErrorCodeFailed),
			"no active mls leaf key; this device cannot sign for its account"), false
	}
	if key.AccountID != accountID {
		return errs.CodeResponse(errs.ErrCodeValidation, "the statement names another account than this device's"), false
	}
	return proto.BaseResponse{}, true
}

func signWithAccountKey(d Deps, canonical string) (string, proto.BaseResponse, bool) {
	accountPriv, err := getPrivateKeySecure(d.Store)
	if err != nil {
		return "", errs.CodeResponse(errs.ErrCodeNotFound, "account keypair not found (signup required first)"), false
	}
	defer accountPriv.Destroy()
	sig, err := signDataSecure(accountPriv, canonical)
	if err != nil {
		return "", errs.CodeResponse(errs.ErrCodeCryptoFailure, "statement signing failed"), false
	}
	return sig, proto.BaseResponse{}, true
}
