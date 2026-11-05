package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

func groupRewrapDecisionFixture(t *testing.T) (*auditFixture, proto.GroupRewrapDecision, groupRewrapContext) {
	t.Helper()
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	binding, found, err := keychain.GetAccountBinding(f.store)
	if err != nil || !found {
		t.Fatalf("account binding unavailable: %v", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	context := groupRewrapContext{
		accountID: f.v.AccountID, deviceID: deviceID,
		tokenID: "66666666-6666-4666-8666-666666666666", sessionStartNanos: 123,
		bindingGeneration: binding.Generation, operation: "member_invite",
		orgID: f.v.OrgID, groupID: f.v.GroupID, dekVersion: f.v.DekVersion,
		sourceKind: "stored_member", sourcePolicy: proto.GrantPolicyLegacy,
		outputPolicy: proto.GrantPolicyLegacy,
		sourceDigest: [32]byte{1}, requestDigest: [32]byte{2}, recipientsDigest: [32]byte{3},
	}
	if err := f.deps.GroupRewrapChallenges.Put(challenge, context, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	decision := proto.GroupRewrapDecision{
		Challenge: challenge, AccountID: context.accountID, DeviceID: context.deviceID,
		TokenID: context.tokenID, SessionIssuedAtNanos: context.sessionStartNanos,
		Operation: context.operation, OrgID: context.orgID, GroupID: context.groupID,
		DEKVersion: context.dekVersion, SourceKind: context.sourceKind,
		SourceGrantDigest: hex.EncodeToString(context.sourceDigest[:]),
		SourcePolicy:      context.sourcePolicy, OutputPolicy: context.outputPolicy,
		RequestDigest:    hex.EncodeToString(context.requestDigest[:]),
		RecipientsDigest: hex.EncodeToString(context.recipientsDigest[:]),
		IssuedAt:         f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9,
		ServerKeyVersion: 1,
	}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	return f, decision, context
}

func TestGroupRewrapDecisionGateRequiresExactLiveRequestAndConsumesOnce(t *testing.T) {
	f, decision, context := groupRewrapDecisionFixture(t)
	changed := context
	changed.recipientsDigest[0]++
	if _, err := verifyAndConsumeGroupRewrapDecision(f.deps, decision, changed); err == nil {
		t.Fatal("different recipient request accepted")
	}
	if _, err := verifyAndConsumeGroupRewrapDecision(f.deps, decision, context); err != nil {
		t.Fatalf("valid signed request refused: %v", err)
	}
	if _, err := verifyAndConsumeGroupRewrapDecision(f.deps, decision, context); err == nil {
		t.Fatal("replayed decision accepted")
	}
}

func TestGroupRewrapDecisionGateRefusesChangedBindingAndKeepsChallenge(t *testing.T) {
	f, decision, context := groupRewrapDecisionFixture(t)
	if _, _, err := keychain.SetAccountBinding(f.store, context.accountID, "alice", true); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAndConsumeGroupRewrapDecision(f.deps, decision, context); err == nil {
		t.Fatal("old login generation accepted")
	}
	if _, pending := f.deps.GroupRewrapChallenges.Peek(decision.Challenge, f.clock.now()); !pending {
		t.Fatal("invalid decision consumed a challenge")
	}
}

func TestGroupRewrapDecisionGateRefusesSignedStatementForAnotherRequest(t *testing.T) {
	for name, change := range map[string]func(*proto.GroupRewrapDecision){
		"operation": func(d *proto.GroupRewrapDecision) { d.Operation = "member_add" },
		"source": func(d *proto.GroupRewrapDecision) {
			d.SourceGrantDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
		},
		"recipients": func(d *proto.GroupRewrapDecision) {
			d.RecipientsDigest = hex.EncodeToString(bytes.Repeat([]byte{8}, 32))
		},
		"requester": func(d *proto.GroupRewrapDecision) { d.AccountID = "77777777-7777-4777-8777-777777777777" },
		"session":   func(d *proto.GroupRewrapDecision) { d.SessionIssuedAtNanos++ },
	} {
		t.Run(name, func(t *testing.T) {
			f, decision, context := groupRewrapDecisionFixture(t)
			change(&decision)
			decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
			if _, err := verifyAndConsumeGroupRewrapDecision(f.deps, decision, context); err == nil {
				t.Fatal("other signed request accepted")
			}
			if _, pending := f.deps.GroupRewrapChallenges.Peek(decision.Challenge, f.clock.now()); !pending {
				t.Fatal("mismatched decision consumed the correct challenge")
			}
		})
	}
}
