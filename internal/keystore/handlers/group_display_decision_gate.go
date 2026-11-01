package handlers

import (
	"encoding/hex"
	"errors"

	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

var errCurrentGroupDisplayDenied = errors.New("current Group display decision denied")

// verifyAndConsumeCurrentGroupDisplayDecision checks one API-signed decision
// against Keeper's exact pending operation and live local binding. A caller
// must hold the request lock through this check and its protected side effect;
// the online API wait must happen before acquiring that lock.
func verifyAndConsumeCurrentGroupDisplayDecision(d Deps, decision proto.CurrentGroupDisplayDecision, handle string) error {
	if d.GroupDisplayChallenges == nil || d.GroupSessions == nil || d.ServerKeyVerifier == nil || d.Store == nil {
		return errCurrentGroupDisplayDenied
	}
	if err := decision.Validate(); err != nil {
		return errCurrentGroupDisplayDenied
	}
	now := d.Now()
	if decision.IssuedAt > now.Unix()+proto.DisplayDecisionClockSkewSeconds || now.Unix() >= decision.ExpiresAt {
		return errCurrentGroupDisplayDenied
	}
	context, ok := d.GroupDisplayChallenges.Peek(decision.Challenge, now)
	if !ok || context.audit || context.groupHandle != handle ||
		context.accountID != decision.AccountID || context.deviceID != decision.DeviceID ||
		context.tokenID != decision.TokenID || context.sessionStartNanos != decision.SessionIssuedAtNanos ||
		context.operationDigest != decodedGroupDisplayDigest(decision.OperationDigest) ||
		context.frameKeyDigest != decodedGroupDisplayDigest(decision.FrameKeyDigest) {
		return errCurrentGroupDisplayDenied
	}
	label, err := d.GroupSessions.LabelOf(handle)
	if err != nil || label.OrgID == "" || label.GroupID != decision.GroupID ||
		label.DekVersion != decision.DekVersion ||
		(label.GrantPolicy != proto.GrantPolicyLegacy && label.GrantPolicy != proto.GrantPolicyDecryptOnlyV1) ||
		label.GrantDigest == [32]byte{} || label.GrantDigest != decodedGroupDisplayDigest(decision.GrantDigest) {
		return errCurrentGroupDisplayDenied
	}
	if err := d.ServerKeyVerifier.Verify(
		proto.CurrentGroupDisplayDecisionCanonical(decision), decision.Signature, decision.ServerKeyVersion,
	); err != nil {
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

func decodedGroupDisplayDigest(value string) [32]byte {
	var digest [32]byte
	decoded, _ := hex.DecodeString(value) // decision.Validate checked canonical lowercase hex.
	copy(digest[:], decoded)
	return digest
}
