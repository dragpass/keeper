package handlers

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/proto"
)

const (
	archivePinOwner  = "11111111-1111-4111-8111-111111111111"
	archivePinMember = "22222222-2222-4222-8222-222222222222"
)

// A break-glass re-grant naming the member account is judged by the member's
// pin: the first key is taken on first use, a later unexplained key refuses
// with nothing wrapped.
func TestArchiveUnwrapAndRewrapEnforcesTheMemberPin(t *testing.T) {
	deps, _, store := newTestDeps(t)
	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrapped, _ := crypto.EncryptData(archivePub, make([]byte, 32))
	wrappedB64 := base64.StdEncoding.EncodeToString(wrapped)
	member, _ := crypto.GenerateRSAKeyPair()
	stranger, _ := crypto.GenerateRSAKeyPair()

	pinned := func(recipient string) proto.BaseResponse {
		return HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
			WrappedForArchiveB64: wrappedB64, RecipientPublicKey: recipient,
			OwnerAccountID: archivePinOwner, RecipientAccountID: archivePinMember,
		})
	}
	if first := pinned(member.PublicKey); !first.Success {
		t.Fatalf("first re-grant: %+v", first)
	}
	changed := pinned(stranger.PublicKey)
	if changed.Success || changed.ErrorCode != string(errs.ErrCodePeerKeyChanged) || changed.Data == nil {
		t.Fatalf("re-grant to a changed key: %+v", changed)
	}
	if _, ok := changed.Data.(proto.ArchiveUnwrapAndRewrapResponseData); ok {
		t.Fatal("a refused re-grant carried a wrap")
	}
	// The Native Messaging shape without account ids keeps its parity.
	if legacy := HandleArchiveUnwrapAndRewrap(deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: wrappedB64, RecipientPublicKey: stranger.PublicKey,
	}); !legacy.Success {
		t.Fatalf("unpinned re-grant: %+v", legacy)
	}
	for name, bad := range map[string]proto.ArchiveUnwrapAndRewrapRequest{
		"a non-uuid owner":  {WrappedForArchiveB64: wrappedB64, RecipientPublicKey: member.PublicKey, OwnerAccountID: "x", RecipientAccountID: archivePinMember},
		"statements alone":  {WrappedForArchiveB64: wrappedB64, RecipientPublicKey: member.PublicKey, RotationStatements: []proto.KeyRotationStatement{{}}},
		"a recipient alone": {WrappedForArchiveB64: wrappedB64, RecipientPublicKey: member.PublicKey, RecipientAccountID: archivePinMember},
	} {
		if response := HandleArchiveUnwrapAndRewrap(deps, bad); response.Success || response.ErrorCode != string(errs.ErrCodeValidation) {
			t.Fatalf("%s: %+v", name, response)
		}
	}
}

// Quorum combine judges every pinned recipient before it reassembles anything.
func TestArchiveQuorumCombineEnforcesRecipientPins(t *testing.T) {
	deps, _, store := newTestDeps(t)
	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)
	adminKPs, adminPems := genAdminKeys(t, 3)
	split := HandleArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{ThresholdN: 2, RecipientPublicKeys: adminPems})
	if !split.Success {
		t.Fatalf("split: %s", split.Error)
	}
	shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
	session := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{})
	sessionPub := session.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey
	rewrapped := []proto.RewrappedShareInput{
		adminRewrapShare(t, adminKPs[0], shares[0], sessionPub),
		adminRewrapShare(t, adminKPs[1], shares[1], sessionPub),
	}
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrappedOld, _ := crypto.EncryptData(archivePub, make([]byte, 32))
	member, _ := crypto.GenerateRSAKeyPair()
	stranger, _ := crypto.GenerateRSAKeyPair()

	combine := func(recipients ...proto.DEKRewrapRecipient) proto.BaseResponse {
		return HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
			RewrappedShares: rewrapped, WrappedOldDEKB64: base64.StdEncoding.EncodeToString(wrappedOld),
			OwnerAccountID: archivePinOwner, Recipients: recipients,
		})
	}
	first := combine(proto.DEKRewrapRecipient{AccountID: archivePinMember, PublicKey: member.PublicKey})
	if !first.Success || len(first.Data.(proto.ArchiveQuorumCombineAndRewrapResponseData).Grants) != 1 {
		t.Fatalf("first combine: %+v", first)
	}
	refused := combine(
		proto.DEKRewrapRecipient{AccountID: "33333333-3333-4333-8333-333333333333", PublicKey: member.PublicKey},
		proto.DEKRewrapRecipient{AccountID: archivePinMember, PublicKey: stranger.PublicKey},
	)
	if refused.Success || refused.ErrorCode != string(errs.ErrCodePeerKeyChanged) {
		t.Fatalf("combine with a changed recipient: %+v", refused)
	}
	none := HandleArchiveQuorumCombineAndRewrap(deps, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares: rewrapped, WrappedOldDEKB64: base64.StdEncoding.EncodeToString(wrappedOld),
		OwnerAccountID: archivePinOwner,
	})
	if none.Success || !strings.Contains(none.Error, "recipients") {
		t.Fatalf("no recipients: %+v", none)
	}
}
