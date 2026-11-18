package handlers

import (
	"encoding/base64"
	"testing"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/errs"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/keytransparency"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/testdouble"
)

// archiveSelfFixture holds a Keeper whose own account key is known, an org
// archive key, and a ready quorum session, so the two archive re-grant paths
// can be called with the owner's own account as a recipient.
type archiveSelfFixture struct {
	deps       Deps
	store      *testdouble.MemorySecretStore
	own        *crypto.KeyPair
	staged     *crypto.KeyPair
	foreign    *crypto.KeyPair
	wrappedB64 string
	rewrapped  []proto.RewrappedShareInput
}

func newArchiveSelfFixture(t *testing.T) archiveSelfFixture {
	t.Helper()
	deps, _, store := newTestDeps(t)
	own, _ := crypto.GenerateRSAKeyPair()
	staged, _ := crypto.GenerateRSAKeyPair()
	foreign, _ := crypto.GenerateRSAKeyPair()
	if err := keychain.SavePublicKey(store, own.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePendingPublicKey(store, staged.PublicKey); err != nil {
		t.Fatal(err)
	}
	archiveKP, _ := crypto.GenerateRSAKeyPair()
	_ = keychain.SaveArchivePrivateKey(store, archiveKP.PrivateKey)
	_ = keychain.SaveArchivePublicKey(store, archiveKP.PublicKey)
	adminKPs, adminPems := genAdminKeys(t, 3)
	split := prepareUnboundArchiveKeySplit(deps, proto.ArchiveKeySplitRequest{OperationID: "44444444-4444-4444-8444-444444444444", ThresholdN: 2, RecipientPublicKeys: adminPems})
	if !split.Success {
		t.Fatalf("split: %s", split.Error)
	}
	shares := split.Data.(proto.ArchiveKeySplitResponseData).Shares
	session := HandleArchiveSessionBegin(deps, proto.ArchiveSessionBeginRequest{OrgID: testOrgA})
	sessionPub := session.Data.(proto.ArchiveSessionBeginResponseData).SessionPublicKey
	archivePub, _ := crypto.ParsePublicKey(archiveKP.PublicKey)
	wrapped, _ := crypto.EncryptData(archivePub, make([]byte, 32))
	return archiveSelfFixture{
		deps: deps, store: store, own: own, staged: staged, foreign: foreign,
		wrappedB64: base64.StdEncoding.EncodeToString(wrapped),
		rewrapped: []proto.RewrappedShareInput{
			adminRewrapShare(t, adminKPs[0], shares[0], sessionPub),
			adminRewrapShare(t, adminKPs[1], shares[1], sessionPub),
		},
	}
}

func (f archiveSelfFixture) withTransparency(t *testing.T) archiveSelfFixture {
	t.Helper()
	_, trust := signedStatementEvidence(t, []byte("archive self recipient"))
	f.deps.KeyTransparency = keytransparency.Gate{Trust: trust}
	return f
}

func (f archiveSelfFixture) withStrictPeers(t *testing.T) archiveSelfFixture {
	t.Helper()
	if err := keychain.SavePeerKeyPolicy(f.store, keychain.PeerKeyPolicy{RequireVerifiedPeers: true}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f archiveSelfFixture) combine(publicKey string) proto.BaseResponse {
	return archiveQuorumCombineAndRewrap(f.deps, testOrgA, proto.ArchiveQuorumCombineAndRewrapRequest{
		RewrappedShares: f.rewrapped, WrappedOldDEKB64: f.wrappedB64,
		OwnerAccountID: archivePinOwner,
		Recipients:     []proto.DEKRewrapRecipient{{AccountID: archivePinOwner, PublicKey: publicKey}},
	})
}

func (f archiveSelfFixture) regrant(publicKey string) proto.BaseResponse {
	return archiveUnwrapAndRewrap(f.deps, proto.ArchiveUnwrapAndRewrapRequest{
		WrappedForArchiveB64: f.wrappedB64, RecipientPublicKey: publicKey,
		OwnerAccountID: archivePinOwner, RecipientAccountID: archivePinOwner,
	})
}

// The coordinator re-granting to itself names its own account. Keeper knows
// its own key, so no pin or log proof is asked for it.
func TestArchiveRegrantToOwnAccountAndOwnKeyNeedsNoProof(t *testing.T) {
	paths := map[string]func(archiveSelfFixture, string) proto.BaseResponse{
		"quorum combine":  archiveSelfFixture.combine,
		"member re-grant": archiveSelfFixture.regrant,
	}
	for name, call := range paths {
		t.Run(name, func(t *testing.T) {
			f := newArchiveSelfFixture(t).withTransparency(t)
			if response := call(f, f.own.PublicKey); !response.Success {
				t.Fatalf("self re-grant without evidence: %s (%s)", response.Error, response.ErrorCode)
			}
			if _, err := keychain.GetPeerKeyPin(f.store, archivePinOwner, archivePinOwner); err == nil {
				t.Fatal("a self re-grant wrote a pin for this Keeper's own account")
			}
		})
	}
}

// The owner account with any key other than the active one is still a peer
// key the server chose, so it keeps the log proof requirement. The staged key
// of an account key rotation is not accepted here: these paths never took it.
func TestArchiveRegrantToOwnAccountWithAnotherKeyStillNeedsProof(t *testing.T) {
	paths := map[string]func(archiveSelfFixture, string) proto.BaseResponse{
		"quorum combine":  archiveSelfFixture.combine,
		"member re-grant": archiveSelfFixture.regrant,
	}
	for name, call := range paths {
		for keyName, pick := range map[string]func(archiveSelfFixture) string{
			"foreign key": func(f archiveSelfFixture) string { return f.foreign.PublicKey },
			"staged key":  func(f archiveSelfFixture) string { return f.staged.PublicKey },
		} {
			t.Run(name+"/"+keyName, func(t *testing.T) {
				f := newArchiveSelfFixture(t).withTransparency(t)
				response := call(f, pick(f))
				if response.Success || response.ErrorCode != string(errs.ErrCodeKeyTransparencyUnverified) {
					t.Fatalf("owner account with %s = %+v, want key_transparency_unverified", keyName, response)
				}
			})
		}
	}
}

// Strict mode refuses peers nobody compared out of band. This Keeper's own key
// is not a peer, so strict mode does not refuse it; a foreign key under the
// owner account is refused as before.
func TestArchiveRegrantSelfInStrictMode(t *testing.T) {
	paths := map[string]func(archiveSelfFixture, string) proto.BaseResponse{
		"quorum combine":  archiveSelfFixture.combine,
		"member re-grant": archiveSelfFixture.regrant,
	}
	for name, call := range paths {
		t.Run(name, func(t *testing.T) {
			f := newArchiveSelfFixture(t).withStrictPeers(t)
			if response := call(f, f.own.PublicKey); !response.Success {
				t.Fatalf("strict self re-grant: %s (%s)", response.Error, response.ErrorCode)
			}
			refused := call(f, f.foreign.PublicKey)
			if refused.Success || refused.ErrorCode != string(errs.ErrCodePeerKeyUnverified) {
				t.Fatalf("strict foreign key under the owner account = %+v, want peer_key_unverified", refused)
			}
		})
	}
}
