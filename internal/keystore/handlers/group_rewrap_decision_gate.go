package handlers

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

var errGroupRewrapDenied = errors.New("group rewrap decision denied")

// verifyAndConsumeGroupRewrapDecision checks one prepared local request and
// signed online decision. The caller must hold requestMu through the ensuing
// key operation; it must finish the online API wait before taking that lock.
func verifyAndConsumeGroupRewrapDecision(d Deps, decision proto.GroupRewrapDecision, execution groupRewrapContext) (time.Time, error) {
	if d.GroupRewrapChallenges == nil || d.ServerKeyVerifier == nil || d.Store == nil || decision.Validate() != nil {
		return time.Time{}, errGroupRewrapDenied
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= decision.ExpiresAt {
		return time.Time{}, errGroupRewrapDenied
	}
	entry, ok := d.GroupRewrapChallenges.peekEntry(decision.Challenge, now)
	context := entry.context
	if !ok || context.accountID != decision.AccountID || context.deviceID != decision.DeviceID ||
		context.tokenID != decision.TokenID || context.sessionStartNanos != decision.SessionIssuedAtNanos ||
		context.operation != decision.Operation || context.orgID != decision.OrgID ||
		context.groupID != decision.GroupID || context.dekVersion != decision.DEKVersion ||
		context.sourceKind != decision.SourceKind ||
		hex.EncodeToString(context.sourceDigest[:]) != decision.SourceGrantDigest ||
		context.sourcePolicy != decision.SourcePolicy || context.outputPolicy != decision.OutputPolicy ||
		hex.EncodeToString(context.requestDigest[:]) != decision.RequestDigest ||
		hex.EncodeToString(context.recipientsDigest[:]) != decision.RecipientsDigest ||
		context.operation != execution.operation || context.orgID != execution.orgID ||
		context.groupID != execution.groupID || context.dekVersion != execution.dekVersion ||
		context.sourceKind != execution.sourceKind || context.sourceDigest != execution.sourceDigest ||
		context.sourcePolicy != execution.sourcePolicy || context.outputPolicy != execution.outputPolicy ||
		context.requestDigest != execution.requestDigest || context.recipientsDigest != execution.recipientsDigest ||
		context.groupHandle != execution.groupHandle {
		return time.Time{}, errGroupRewrapDenied
	}
	if err := d.ServerKeyVerifier.Verify(proto.GroupRewrapDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion); err != nil {
		return time.Time{}, errGroupRewrapDenied
	}
	binding, found, err := keychain.GetAccountBinding(d.Store)
	if err != nil || !found || binding.SignedOut || binding.AccountID != context.accountID ||
		binding.Generation == 0 || binding.Generation != context.bindingGeneration {
		return time.Time{}, errGroupRewrapDenied
	}
	deviceID, found, err := keychain.GetDeviceID(d.Store)
	if err != nil || !found || deviceID != context.deviceID {
		return time.Time{}, errGroupRewrapDenied
	}
	finalNow := d.Now()
	if finalNow.Unix() >= decision.ExpiresAt {
		return time.Time{}, errGroupRewrapDenied
	}
	consumed, ok := d.GroupRewrapChallenges.Consume(decision.Challenge, finalNow)
	if !ok || consumed != context {
		return time.Time{}, errGroupRewrapDenied
	}
	return entry.expiresAt, nil
}
