package handlers

import (
	"reflect"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestAuthorizedMemberRewrapRefusesMissingDecisionBeforeKeychainMutation(t *testing.T) {
	f := newAuditFixture(t)
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		OtherPublicKey:  target.PublicKey, OwnerAccountID: f.v.AccountID,
		OtherAccountID: "77777777-7777-4777-8777-777777777777",
		GrantContext:   legacyContext(f.v),
	}
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	resp := HandleAuthorizedDEKRewrapForMember(f.deps, req)
	if resp.Success || resp.ErrorCode != "not_found" || resp.Data != nil {
		t.Fatalf("missing decision must be refused before rewrap: success=%t code=%s", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("missing decision changed keychain state")
	}
}

func TestAuthorizedManyRewrapRefusesMissingDecisionBeforeKeychainMutation(t *testing.T) {
	f := newAuditFixture(t)
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		OwnerAccountID:  f.v.AccountID,
		Recipients: []proto.DEKRewrapRecipient{{
			AccountID: "77777777-7777-4777-8777-777777777777", PublicKey: target.PublicKey,
		}},
		GrantContext: legacyContext(f.v),
	}
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	resp := HandleAuthorizedDEKUnwrapAndRewrapForMany(f.deps, req)
	if resp.Success || resp.ErrorCode != "not_found" || resp.Data != nil {
		t.Fatalf("missing decision must be refused before batch rewrap: success=%t code=%s", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("missing decision changed keychain state")
	}
}

func TestAuthorizedManyRewrapRejectsChangedLateRecipientAndConsumesOnce(t *testing.T) {
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	first, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	last, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		OwnerAccountID:  f.v.AccountID, GrantContext: legacyContext(f.v),
		Operation: "rotation_old_grants", SourceKind: "stored_member",
		Recipients: []proto.DEKRewrapRecipient{
			{AccountID: "77777777-7777-4777-8777-777777777777", PublicKey: first.PublicKey},
			{AccountID: "88888888-8888-4888-8888-888888888888", PublicKey: last.PublicKey},
		},
	}
	prepared := HandleGroupRewrapPrepare(f.deps, proto.GroupRewrapPrepareRequest{
		Operation: req.Operation, SourceKind: req.SourceKind,
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Many: &req,
	})
	if !prepared.Success {
		t.Fatalf("prepare refused: %s", prepared.ErrorCode)
	}
	data := prepared.Data.(proto.GroupRewrapPrepareResponseData)
	decision := proto.GroupRewrapDecision{
		Challenge: data.Challenge, AccountID: f.v.AccountID, DeviceID: deviceID,
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Operation: data.Operation, OrgID: data.OrgID, GroupID: data.GroupID,
		DEKVersion: data.DEKVersion, SourceKind: data.SourceKind,
		SourceGrantDigest: data.SourceGrantDigest, SourcePolicy: data.SourcePolicy,
		OutputPolicy: data.OutputPolicy, RequestDigest: data.RequestDigest,
		RecipientsDigest: data.RecipientsDigest, IssuedAt: f.clock.now().Unix() - 1,
		ExpiresAt: f.clock.now().Unix() + 9, ServerKeyVersion: 1,
	}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	req.Decision = &decision
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	changed := req
	changed.Recipients = append([]proto.DEKRewrapRecipient(nil), req.Recipients...)
	other, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	changed.Recipients[1].PublicKey = other.PublicKey
	if resp := HandleAuthorizedDEKUnwrapAndRewrapForMany(f.deps, changed); resp.Success || resp.ErrorCode != "not_found" || resp.Data != nil {
		t.Fatalf("changed last recipient accepted: success=%t code=%s", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("changed last recipient wrote a peer pin")
	}
	if resp := HandleAuthorizedDEKUnwrapAndRewrapForMany(f.deps, req); !resp.Success {
		t.Fatalf("signed batch refused: %s", resp.ErrorCode)
	}
	if resp := HandleAuthorizedDEKUnwrapAndRewrapForMany(f.deps, req); resp.Success {
		t.Fatal("same signed batch decision authorized twice")
	}
}

func TestAuthorizedMemberRewrapUsesPreparedSignedDecisionOnce(t *testing.T) {
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	deviceID := "55555555-5555-4555-8555-555555555555"
	if err := f.store.Set(config.Service, config.DeviceID, deviceID); err != nil {
		t.Fatal(err)
	}
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	req := proto.DEKRewrapForMemberRequest{
		WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
		OtherPublicKey:  target.PublicKey, OwnerAccountID: f.v.AccountID,
		OtherAccountID: "77777777-7777-4777-8777-777777777777",
		GrantContext:   legacyContext(f.v),
		Operation:      "member_invite", SourceKind: "stored_member",
	}
	prepared := HandleGroupRewrapPrepare(f.deps, proto.GroupRewrapPrepareRequest{
		Operation: req.Operation, SourceKind: req.SourceKind,
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Member: req,
	})
	if !prepared.Success {
		t.Fatalf("prepare refused: %s", prepared.ErrorCode)
	}
	data := prepared.Data.(proto.GroupRewrapPrepareResponseData)
	decision := proto.GroupRewrapDecision{
		Challenge: data.Challenge, AccountID: f.v.AccountID, DeviceID: deviceID,
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Operation: data.Operation, OrgID: data.OrgID, GroupID: data.GroupID,
		DEKVersion: data.DEKVersion, SourceKind: data.SourceKind,
		SourceGrantDigest: data.SourceGrantDigest,
		SourcePolicy:      data.SourcePolicy, OutputPolicy: data.OutputPolicy,
		RequestDigest: data.RequestDigest, RecipientsDigest: data.RecipientsDigest,
		IssuedAt: f.clock.now().Unix() - 1, ExpiresAt: f.clock.now().Unix() + 9,
		ServerKeyVersion: 1,
	}
	decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
	req.Decision = &decision
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	changed := req
	changed.WrappedForMeB64 = "YQ=="
	if resp := HandleAuthorizedDEKRewrapForMember(f.deps, changed); resp.Success || resp.ErrorCode != "not_found" {
		t.Fatalf("changed source accepted: %t %s", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("changed source modified keychain before authorization")
	}
	otherTarget, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	changed = req
	changed.OtherPublicKey = otherTarget.PublicKey
	if resp := HandleAuthorizedDEKRewrapForMember(f.deps, changed); resp.Success || resp.ErrorCode != "not_found" {
		t.Fatalf("changed recipient accepted: %t %s", resp.Success, resp.ErrorCode)
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("changed recipient modified keychain before authorization")
	}
	if resp := HandleAuthorizedDEKRewrapForMember(f.deps, req); !resp.Success {
		t.Fatalf("signed decision refused: %s", resp.ErrorCode)
	}
	if resp := HandleAuthorizedDEKRewrapForMember(f.deps, req); resp.Success {
		t.Fatal("same signed decision authorized a second rewrap")
	}
}
