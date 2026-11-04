package handlers

import (
	"reflect"
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

func TestGroupRewrapPrepareBindsStoredMemberSourceWithoutWrapping(t *testing.T) {
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	if err := f.store.Set(config.Service, config.DeviceID, "55555555-5555-4555-8555-555555555555"); err != nil {
		t.Fatal(err)
	}
	target, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	request := proto.GroupRewrapPrepareRequest{
		Operation: "member_invite", SourceKind: "stored_member",
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Member: proto.DEKRewrapForMemberRequest{
			WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
			OtherPublicKey:  target.PublicKey, OwnerAccountID: f.v.AccountID,
			OtherAccountID: "77777777-7777-4777-8777-777777777777",
			GrantContext:   legacyContext(f.v),
		},
	}
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	response := HandleGroupRewrapPrepare(f.deps, request)
	if !response.Success {
		t.Fatalf("prepare refused: %s (%s)", response.Error, response.ErrorCode)
	}
	data, ok := response.Data.(proto.GroupRewrapPrepareResponseData)
	if !ok || data.Challenge == "" || data.SourceGrantDigest == "" || data.RequestDigest == "" || data.RecipientsDigest == "" {
		t.Fatalf("incomplete preparation: %#v", response.Data)
	}
	if f.deps.GroupRewrapChallenges.Len() != 1 {
		t.Fatal("prepare did not keep exactly one challenge")
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("prepare modified keychain state before authorization")
	}
}

func TestGroupRewrapPrepareBindsEntireBatchWithoutWrapping(t *testing.T) {
	f := newAuditFixture(t)
	f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
	if err := f.store.Set(config.Service, config.DeviceID, "55555555-5555-4555-8555-555555555555"); err != nil {
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
	request := proto.GroupRewrapPrepareRequest{
		Operation: "rotation_old_grants", SourceKind: "stored_member",
		TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123,
		Many: &proto.DEKUnwrapAndRewrapForManyRequest{
			WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)),
			OwnerAccountID:  f.v.AccountID, GrantContext: legacyContext(f.v),
			Recipients: []proto.DEKRewrapRecipient{
				{AccountID: "77777777-7777-4777-8777-777777777777", PublicKey: first.PublicKey},
				{AccountID: "88888888-8888-4888-8888-888888888888", PublicKey: last.PublicKey},
			},
		},
	}
	before := f.store.(*testdouble.MemorySecretStore).Snapshot()
	response := HandleGroupRewrapPrepare(f.deps, request)
	if !response.Success {
		t.Fatalf("prepare refused: %s", response.ErrorCode)
	}
	data := response.Data.(proto.GroupRewrapPrepareResponseData)
	if data.Challenge == "" || data.RequestDigest == "" || data.RecipientsDigest == "" {
		t.Fatal("batch preparation omitted its commitments")
	}
	if !reflect.DeepEqual(before, f.store.(*testdouble.MemorySecretStore).Snapshot()) {
		t.Fatal("batch preparation changed keychain state")
	}
}
