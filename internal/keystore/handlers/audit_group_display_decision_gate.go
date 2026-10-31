package handlers

import (
	"crypto/sha256"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A caller holds requestMu through this check and the protected operation.
func verifyAndConsumeAuditGroupDisplayDecision(d Deps, decision proto.AuditGroupDisplayDecision, handle string) error {
	if d.GroupDisplayChallenges == nil || d.GroupSessions == nil || d.ServerKeyVerifier == nil || d.Store == nil || decision.Validate() != nil {
		return errCurrentGroupDisplayDenied
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+5 || now.Unix() >= decision.ExpiresAt {
		return errCurrentGroupDisplayDenied
	}
	context, ok := d.GroupDisplayChallenges.Peek(decision.Challenge, now)
	if !ok || !context.audit || context.groupHandle != handle || context.accountID != decision.AccountID ||
		context.deviceID != decision.DeviceID || context.tokenID != decision.TokenID ||
		context.sessionStartNanos != decision.SessionIssuedAtNanos ||
		context.operationDigest != decodedGroupDisplayDigest(decision.OperationDigest) ||
		context.frameKeyDigest != decodedGroupDisplayDigest(decision.FrameKeyDigest) ||
		context.auditTableID != decision.TableID || context.auditTableDigest != decodedGroupDisplayDigest(decision.TableDigest) {
		return errCurrentGroupDisplayDenied
	}
	label, err := d.GroupSessions.LabelOf(handle)
	if err != nil || label.GrantPolicy != proto.GrantPolicyAuditOnlyV1 || label.OrgID == "" ||
		label.GroupID != decision.GroupID || label.DekVersion != decision.DekVersion ||
		label.GrantDigest == [sha256.Size]byte{} || label.GrantDigest != decodedGroupDisplayDigest(decision.GrantDigest) {
		return errCurrentGroupDisplayDenied
	}
	if d.ServerKeyVerifier.Verify(proto.AuditGroupDisplayDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion) != nil {
		return errCurrentGroupDisplayDenied
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != context.accountID ||
		binding.Generation == 0 || binding.Generation != context.bindingGeneration {
		return errCurrentGroupDisplayDenied
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || deviceID != context.deviceID {
		return errCurrentGroupDisplayDenied
	}
	finalNow := d.Now()
	if finalNow.Unix() >= decision.ExpiresAt {
		return errCurrentGroupDisplayDenied
	}
	consumed, ok := d.GroupDisplayChallenges.Consume(decision.Challenge, finalNow)
	if !ok || consumed != context {
		return errCurrentGroupDisplayDenied
	}
	return nil
}
