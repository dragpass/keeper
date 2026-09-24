//go:build mls && cgo

// Account recovery is a new MLS identity, never a succession (design §0.3
// policy 1, Q2): RK24 recovery registers a new account key, the recovered
// device's leaf carries it, and the peers' Keepers take it in only when a
// person asks them to (a room's owner or admin, or the DM peer), never
// through automation. The test stands in for ariadne and for the recovery
// itself: it mints the new account key and the recovery rotation statement.

package dispatch

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

// recoveredKeeper is what RK24 recovery leaves on a new machine of of's
// account: a new account key pair, the recovery rotation statement from the
// old key to it, and nothing else. No leaf is enrolled.
func recoveredKeeper(t *testing.T, of *keeper, device string) (*keeper, proto.KeyRotationStatement) {
	t.Helper()
	oldPEM, err := keychain.GetPublicKey(of.store)
	if err != nil {
		t.Fatal(err)
	}
	oldPrivPEM, err := keychain.GetPrivateKey(of.store)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store := keychain.NewMemorySecretStore()
	if err := keychain.SavePrivateKey(store, pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	st := proto.KeyRotationStatement{
		AccountID:      of.id,
		OldFingerprint: crypto.AccountKeyFingerprint([]byte(oldPEM)),
		NewFingerprint: crypto.AccountKeyFingerprint([]byte(pair.PublicKey)),
		RotatedAt:      time.Now().Unix(),
		Reason:         proto.KeyRotationReasonRecovery,
		OldPublicKey:   base64.StdEncoding.EncodeToString([]byte(oldPEM)),
		NewPublicKey:   base64.StdEncoding.EncodeToString([]byte(pair.PublicKey)),
	}
	sign := func(privPEM string) string {
		priv, err := crypto.ParsePrivateKey(privPEM)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := crypto.SignData(priv, st.Canonical())
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	st.OldSignature, st.NewSignature = sign(oldPrivPEM), sign(pair.PrivateKey)
	return &keeper{
		t: t, id: of.id, device: device, store: store,
		root: filepath.Join(t.TempDir(), "chat-state-"+device[:8]),
		deps: handlers.Deps{
			Logger:            logger.NewMemoryLogger(),
			Store:             store,
			ServerKeyVerifier: verifier.AlwaysOKVerifier{},
		},
	}, st
}

func (k *keeper) buildRecoveryReplace(expected uint64, kp proto.MLSMemberKeyPackage, userInitiated bool,
	chain ...proto.KeyRotationStatement,
) proto.BaseResponse {
	k.t.Helper()
	return k.call(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected,
		Replace: []proto.MLSReplaceMember{replaceOf(kp)}, UserInitiated: userInitiated,
		RotationStatements: chain,
	})
}

// Q2's repro. Bob lost his device and recovered on Bob2 with RK24. Alice's
// automation seats Bob2 in their DM on the permit's word, and nobody on
// Alice's side decided it. It must wait for Alice to confirm.
func TestMLSRecovery_AutomationNeverSeatsARecoveredIdentity(t *testing.T) {
	c := newDM(t)
	bob2, chain := recoveredKeeper(t, c.bob, e2eDevice2)
	oldBob, _, _ := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	listed := []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	c.alice.replacing, c.bob.replacing, bob2.replacing = listed, listed, listed

	resp := c.alice.buildRecoveryReplace(1, bob2.keyPackage(), false, chain)
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("an automated seat of a recovered identity = %+v; want %s", resp, proto.ChatMLSErrorCodeCommitUnauthorized)
	}
	// Sends stay blocked until the lawful Commit lands.
	c.alice.refused(proto.MLSEncrypt, c.alice.encryptRequest(messageID(1), 1, "x"),
		proto.ChatMLSErrorCodeLeafReplacementPending)
}

// The DM peer confirms once: Alice seats the recovered Bob2 with a replace
// she asked for, carrying the recovery chain. Her pin for Bob moves to
// rotated (a new identity, never verified by the move), Bob2 joins and reads
// only what comes after.
func TestMLSRecovery_TheDMPeerSeatsTheRecoveredIdentityOnce(t *testing.T) {
	c := newDM(t)
	before := c.send(c.alice, 1, 1, "before the recovery")
	bob2, chain := recoveredKeeper(t, c.bob, e2eDevice2)
	oldBob, _, _ := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	listed := []proto.ChatStateLeafReplacement{{AccountID: c.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	c.alice.replacing, c.bob.replacing, bob2.replacing = listed, listed, listed

	// Without the chain the new account key is an unexplained change.
	resp := c.alice.buildRecoveryReplace(1, bob2.keyPackage(), true)
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeLeafUntrusted {
		t.Fatalf("a recovered identity without its chain = %+v", resp)
	}

	built := commitOf(mustSucceed(t, "alice seats bob2", c.alice.buildRecoveryReplace(1, bob2.keyPackage(), true, chain)))
	if len(built.LeafTrust) != 1 || built.LeafTrust[0].State != "rotated" {
		t.Fatalf("leaf trust = %+v; want bob rotated", built.LeafTrust)
	}
	c.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	// Bob's old device, if it is found again, still holds the account key the
	// recovery replaced, so it refuses a leaf claiming its own account under
	// another key and stays where it was: it is out of the group either way.
	req := c.bob.processRequest(c.nextSeq(), 2, built.CommitB64)
	req.RotationStatements = []proto.KeyRotationStatement{chain}
	c.bob.refused(proto.MLSProcess, req, proto.ChatMLSErrorCodeLeafUntrusted)
	bob2.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob2.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	})
	c.alice.replacing, bob2.replacing = nil, nil
	pin, err := keychain.GetPeerKeyPin(c.alice.store, c.alice.id, c.bob.id)
	if err != nil || pin.State != keychain.PeerKeyPinStateRotated {
		t.Fatalf("alice's pin for bob = %+v, %v; want rotated", pin, err)
	}

	got := c.alice.decrypt(c.send(bob2, 2, 2, "recovered"))
	if plaintextOf(t, got.PlaintextB64[0]) != "recovered" || got.Items[0].SenderDeviceID != e2eDevice2 {
		t.Fatalf("alice read %+v", got.Items[0])
	}
	if old := bob2.decrypt(before); old.Items[0].State != proto.MLSDisplayItemStateBeforeJoin {
		t.Fatalf("bob2 sees the pre-recovery message as %+v", old.Items[0])
	}
}

// In a room, Carol applies the recovered identity Alice seated: the account
// key changed over a verified chain and the committer is another account. A
// device of the same account key is no recovery, so a person asking to seat
// it without a handover is still refused.
func TestMLSRecovery_ARoomMemberAppliesAPersonsSeatOfARecoveredIdentity(t *testing.T) {
	r := newRoom(t)
	bob2, chain := recoveredKeeper(t, r.bob, e2eDevice2)
	oldBob, _, _ := keychain.GetMLSLeafNewest(r.alice.store, r.alice.id, r.bob.id)
	decl := bob2.declare(proto.MLSLeafReasonRotate, oldBob.NotBefore+60)
	listed := []proto.ChatStateLeafReplacement{{AccountID: r.bob.id, NewSignatureKeyFP: decl.SignatureKeyFingerprint}}
	r.alice.replacing, r.bob.replacing, r.carol.replacing, bob2.replacing = listed, listed, listed, listed

	built := commitOf(mustSucceed(t, "alice seats bob2", r.alice.buildRecoveryReplace(2, bob2.keyPackage(), true, chain)))
	r.alice.confirm(built.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := r.carol.processWith(r.nextSeq(), 3, built.CommitB64, []proto.KeyRotationStatement{chain}); got.Epoch != 3 {
		t.Fatalf("carol applied the seat as %+v", got)
	}

	r2, _, _, kp := takeoverRoom(t)
	resp := r2.alice.buildRecoveryReplace(2, kp, true)
	if resp.Success || string(resp.ErrorCode) != proto.ChatMLSErrorCodeCommitUnauthorized {
		t.Fatalf("a person seating a same-key device without a handover = %+v", resp)
	}
}

func (k *keeper) processWith(
	seq, epoch uint64, commitB64 string, chain []proto.KeyRotationStatement,
) proto.MLSProcessResponseData {
	k.t.Helper()
	req := k.processRequest(seq, epoch, commitB64)
	req.RotationStatements = chain
	return k.must(proto.MLSProcess, req).Data.(proto.MLSProcessResponseData)
}
