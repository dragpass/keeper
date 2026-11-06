package handlers

import (
	"testing"

	"github.com/dragpass/keeper/config"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

// A platform keychain may block after admission; model time advancing there.
type rewrapDelayedKeyStore struct {
	keychain.SecretStore
	onPrivateRead func()
}

func (s rewrapDelayedKeyStore) Get(service, account string) (string, error) {
	value, err := s.SecretStore.Get(service, account)
	if account == config.DragPassKeeperPrivateKey {
		s.onPrivateRead()
	}
	return value, err
}

func TestAuthorizedRewrapDoesNotReleaseOutputAfterDecisionExpiry(t *testing.T) {
	for _, tc := range []struct {
		name                                         string
		batch                                        bool
		serverOffset, beforeExecution, duringKeyRead int64
	}{
		{"member", false, -1, 0, 10},
		{"batch", true, -1, 0, 10},
		{"member_server_ahead", false, 40, 45, 0},
		{"batch_server_ahead", true, 40, 45, 0},
		{"member_challenge_expires_during_key_read", false, 5, 0, 11},
		{"batch_challenge_expires_during_key_read", true, 5, 0, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := tc.batch
			f := newAuditFixture(t)
			f.deps.GroupRewrapChallenges = NewGroupRewrapChallengeStore()
			device := "55555555-5555-4555-8555-555555555555"
			if err := f.store.Set(config.Service, config.DeviceID, device); err != nil {
				t.Fatal(err)
			}
			peer, err := crypto.GenerateRSAKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			member := proto.DEKRewrapForMemberRequest{
				WrappedForMeB64: f.wrapToMe(t, f.pubPEM, legacyContext(f.v)), OtherPublicKey: peer.PublicKey,
				OwnerAccountID: f.v.AccountID, OtherAccountID: "77777777-7777-4777-8777-777777777777",
				GrantContext: legacyContext(f.v), Operation: "member_invite", SourceKind: "stored_member",
			}
			many := proto.DEKUnwrapAndRewrapForManyRequest{
				WrappedForMeB64: member.WrappedForMeB64, OwnerAccountID: member.OwnerAccountID,
				GrantContext: member.GrantContext, Operation: "rotation_old_grants", SourceKind: "stored_member",
				Recipients: []proto.DEKRewrapRecipient{{AccountID: member.OtherAccountID, PublicKey: peer.PublicKey}},
			}
			request := proto.GroupRewrapPrepareRequest{Operation: member.Operation, SourceKind: member.SourceKind,
				TokenID: "66666666-6666-4666-8666-666666666666", SessionIssuedAtNanos: 123, Member: member}
			if batch {
				request.Operation = many.Operation
				request.Many = &many
				request.Member = proto.DEKRewrapForMemberRequest{}
			}
			prepared := HandleGroupRewrapPrepare(f.deps, request)
			if !prepared.Success {
				t.Fatalf("prepare refused: %s", prepared.ErrorCode)
			}
			c := prepared.Data.(proto.GroupRewrapPrepareResponseData)
			decision := proto.GroupRewrapDecision{Challenge: c.Challenge, AccountID: f.v.AccountID, DeviceID: device,
				TokenID: request.TokenID, SessionIssuedAtNanos: 123, Operation: c.Operation, OrgID: c.OrgID, GroupID: c.GroupID,
				DEKVersion: c.DEKVersion, SourceKind: c.SourceKind, SourceGrantDigest: c.SourceGrantDigest,
				SourcePolicy: c.SourcePolicy, OutputPolicy: c.OutputPolicy, RequestDigest: c.RequestDigest, RecipientsDigest: c.RecipientsDigest,
				IssuedAt: f.clock.now().Unix() + tc.serverOffset, ExpiresAt: f.clock.now().Unix() + tc.serverOffset + 10, ServerKeyVersion: 1}
			decision.Signature = f.sign(t, proto.GroupRewrapDecisionCanonical(decision))
			member.Decision = &decision
			many.Decision = &decision
			reached := false
			f.deps.Store = rewrapDelayedKeyStore{SecretStore: f.store, onPrivateRead: func() {
				if !reached {
					reached = true
					f.clock.advance(tc.duringKeyRead)
				}
			}}
			f.clock.advance(tc.beforeExecution)
			var response proto.BaseResponse
			if batch {
				response = HandleAuthorizedDEKUnwrapAndRewrapForMany(f.deps, many)
			} else {
				response = HandleAuthorizedDEKRewrapForMember(f.deps, member)
			}
			if tc.beforeExecution == 0 && !reached {
				t.Fatal("private-key read delay was not reached")
			}
			if tc.beforeExecution > 0 && reached {
				t.Fatal("an aged challenge reached private-key access")
			}
			if response.Success || response.Data != nil {
				t.Fatal("expired decision released wrapped output")
			}
			if f.deps.GroupRewrapChallenges.Len() != 0 {
				t.Fatal("expired operation retained a reusable challenge")
			}
		})
	}
}
