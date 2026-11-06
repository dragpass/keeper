package proto

import "testing"

func TestGroupRewrapRequestDigestBindsExactMemberAndBatchInputs(t *testing.T) {
	memberDigest := func(r DEKRewrapForMemberRequest) [32]byte {
		digest, err := GroupRewrapMemberRequestDigest(r)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	batchDigest := func(r DEKUnwrapAndRewrapForManyRequest) [32]byte {
		digest, err := GroupRewrapManyRequestDigest(r)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	member := DEKRewrapForMemberRequest{
		WrappedForMeB64: "c291cmNl", OtherPublicKey: "key-a",
		OwnerAccountID: "owner", OtherAccountID: "recipient",
		GrantContext: &GrantContext{Policy: GrantPolicyLegacy, OrgID: "org", GroupID: "group", DekVersion: 2},
	}
	wantMember := memberDigest(member)
	for _, changed := range []DEKRewrapForMemberRequest{
		func() DEKRewrapForMemberRequest { r := member; r.WrappedForMeB64 = "b3RoZXI="; return r }(),
		func() DEKRewrapForMemberRequest { r := member; r.OtherPublicKey = "key-b"; return r }(),
		func() DEKRewrapForMemberRequest { r := member; r.OtherAccountID = "other"; return r }(),
		func() DEKRewrapForMemberRequest {
			r := member
			r.RotationStatements = []KeyRotationStatement{{AccountID: "other"}}
			return r
		}(),
		func() DEKRewrapForMemberRequest {
			r := member
			c := *r.GrantContext
			c.DekVersion++
			r.GrantContext = &c
			return r
		}(),
	} {
		if memberDigest(changed) == wantMember {
			t.Fatal("changed member request kept its digest")
		}
	}
	batch := DEKUnwrapAndRewrapForManyRequest{
		WrappedForMeB64: member.WrappedForMeB64,
		OwnerAccountID:  "owner", GrantContext: member.GrantContext,
		Recipients: []DEKRewrapRecipient{{AccountID: "first", PublicKey: "key-a"}, {AccountID: "second", PublicKey: "key-b"}},
	}
	wantBatch := batchDigest(batch)
	batch.Recipients[1].PublicKey = "key-c"
	if batchDigest(batch) == wantBatch {
		t.Fatal("later recipient change kept batch digest")
	}
}
