//go:build mls && cgo

// The MLS chat actions end to end through the dispatcher: each Keeper is its
// own keyring and its own owner partition of the chat state root, every call
// is a Native Messaging request framed as JSON and routed by HandleRequest,
// and the only thing standing in for ariadne is this test deciding which
// Commit won an epoch and handing each Keeper what the server would.

package dispatch

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/chatstate"
	"github.com/dragpass/keeper/internal/keystore/crypto"
	"github.com/dragpass/keeper/internal/keystore/handlers"
	"github.com/dragpass/keeper/internal/keystore/keychain"
	"github.com/dragpass/keeper/internal/keystore/logger"
	"github.com/dragpass/keeper/internal/keystore/proto"
	"github.com/dragpass/keeper/internal/keystore/verifier"
)

const (
	e2eOrg    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	e2eConv   = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	e2eAlice  = "a1111111-1111-4111-8111-111111111111"
	e2eBob    = "b2222222-2222-4222-8222-222222222222"
	e2eDevice = "d1111111-1111-4111-8111-111111111111"
	e2eNonce  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// keeper is one device: its keyring, its Deps, and the account it signs as.
type keeper struct {
	t       *testing.T
	id      string
	store   *keychain.MemorySecretStore
	deps    handlers.Deps
	commits int
}

func newKeeper(t *testing.T, id string) *keeper {
	t.Helper()
	store := keychain.NewMemorySecretStore()
	pair, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePrivateKey(store, pair.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := keychain.SavePublicKey(store, pair.PublicKey); err != nil {
		t.Fatal(err)
	}
	k := &keeper{t: t, id: id, store: store, deps: handlers.Deps{
		Logger:            logger.NewMemoryLogger(),
		Store:             store,
		ServerKeyVerifier: verifier.AlwaysOKVerifier{},
	}}
	k.declare(proto.MLSLeafReasonEnroll, time.Now().Unix())
	return k
}

func e2eStateRoot(t *testing.T) {
	t.Helper()
	t.Setenv(chatstate.RootEnvVar, filepath.Join(t.TempDir(), "chat-state"))
}

// call frames one request the way the extension does and routes it.
func (k *keeper) call(action string, payload any) proto.BaseResponse {
	k.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		k.t.Fatal(err)
	}
	msg, err := json.Marshal(proto.BaseRequest{Action: action, RequestID: "r", Payload: body})
	if err != nil {
		k.t.Fatal(err)
	}
	return HandleRequest(k.deps.Logger, k.deps, msg)
}

func (k *keeper) must(action string, payload any) proto.BaseResponse {
	k.t.Helper()
	resp := k.call(action, payload)
	if !resp.Success {
		k.t.Fatalf("%s as %s: %s (%s)", action, k.id[:8], resp.Error, resp.ErrorCode)
	}
	return resp
}

func (k *keeper) refused(action string, payload any, code string) {
	k.t.Helper()
	resp := k.call(action, payload)
	if resp.Success || string(resp.ErrorCode) != code {
		k.t.Fatalf("%s as %s = %+v; want %s", action, k.id[:8], resp, code)
	}
}

// declare runs mls_leaf_declare then mls_leaf_promote: how a device's leaf key
// becomes the one it signs with, at enrolment and at every rotation.
func (k *keeper) declare(reason string, notBefore int64) {
	k.t.Helper()
	resp := k.must(proto.ActionMLSLeafDeclare, proto.MLSLeafDeclareRequest{
		ChallengeToken: "dragpass.mls.leaf.challenge|1|" + k.id + "|" + e2eDevice + "|" + e2eNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSLeafChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       k.id,
		DeviceID:        e2eDevice,
		NotBefore:       notBefore,
		NotAfter:        notBefore + proto.MLSLeafMaxValiditySeconds,
		Reason:          reason,
	})
	d := resp.Data.(proto.MLSLeafDeclareResponseData).MLSLeafDeclaration
	k.must(proto.ActionMLSLeafPromote, proto.MLSLeafPromoteRequest{
		AcceptanceToken: proto.MLSLeafAcceptedToken(d.AccountID, d.DeviceID, d.SignatureKeyFingerprint, d.NotBefore, d.NotAfter),
		ServerSignature: "any",
	})
}

func (k *keeper) keyPackage() proto.MLSMemberKeyPackage {
	k.t.Helper()
	resp := k.must(proto.MLSKeyPackageGenerate, proto.MLSKeyPackageGenerateRequest{
		ChallengeToken: "dragpass.mls.keypackage.challenge|1|" + k.id + "|" + e2eDevice + "|" + e2eNonce + "|" +
			strconv.FormatInt(time.Now().Unix()+proto.MLSKeyPackageChallengeTTLSeconds, 10),
		ServerSignature: "any",
		AccountID:       k.id,
		DeviceID:        e2eDevice,
		Count:           1,
	})
	kp := resp.Data.(proto.MLSKeyPackageGenerateResponseData).KeyPackages[0]
	return proto.MLSMemberKeyPackage{AccountID: k.id, DeviceID: e2eDevice, KeyPackageB64: kp.KeyPackageB64}
}

// permit is what ariadne would sign for this account. The signature is not
// under test here (the gate tests are in handlers); AlwaysOKVerifier accepts
// it, and everything else about it is what the server would send.
func (k *keeper) permit(removals ...string) proto.ChatStatePermit {
	now := time.Now().Unix()
	if removals == nil {
		removals = []string{}
	}
	return proto.ChatStatePermit{
		AccountID: k.id, OrgID: e2eOrg, ConversationID: e2eConv,
		PendingRemovalAccountIDs: removals,
		IssuedAt:                 now,
		ExpiresAt:                now + proto.ChatStatePermitTTLSeconds,
		ServerKeyVersion:         1,
		Signature:                base64.StdEncoding.EncodeToString([]byte("signed by the test server")),
	}
}

func (k *keeper) nextCommitID() string {
	k.commits++
	return k.id[:8] + "-7777-4777-8777-" + strconv.FormatInt(int64(700000000000+k.commits), 10)
}

func commitOf(resp proto.BaseResponse) proto.MLSCommitResponseData {
	return resp.Data.(proto.MLSCommitResponseData)
}

func (k *keeper) confirm(id, outcome, winnerB64 string) proto.MLSCommitConfirmResponseData {
	k.t.Helper()
	return k.must(proto.MLSCommitConfirm, proto.MLSCommitConfirmRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Outcome: outcome, WinnerCommitB64: winnerB64,
	}).Data.(proto.MLSCommitConfirmResponseData)
}

func (k *keeper) buildUpdate(expected uint64) proto.MLSCommitResponseData {
	k.t.Helper()
	return commitOf(k.must(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: k.nextCommitID(), ExpectedEpoch: expected, UpdateSelf: true,
	}))
}

func (k *keeper) processRequest(seq, epoch uint64, commitB64 string) proto.MLSProcessRequest {
	return proto.MLSProcessRequest{
		Permit: k.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		Seq: seq, Epoch: epoch, CommitB64: commitB64,
	}
}

func (k *keeper) process(seq, epoch uint64, commitB64 string) proto.MLSProcessResponseData {
	k.t.Helper()
	return k.must(proto.MLSProcess, k.processRequest(seq, epoch, commitB64)).Data.(proto.MLSProcessResponseData)
}

// dm is Alice and Bob in one conversation, both confirmed at epoch 1: Alice
// creates it with Bob's KeyPackage, the server accepts her Add, and Bob joins
// from the Welcome the accepted row carries.
type dm struct {
	alice, bob *keeper
	seq        uint64
}

func newDM(t *testing.T) *dm {
	t.Helper()
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)

	id := alice.nextCommitID()
	create := proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: id, Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}
	built := commitOf(alice.must(proto.MLSGroupCreate, create))
	if !built.Created || built.ExpectedEpoch != 0 || built.WelcomeB64 == "" || built.WelcomeReleasable {
		t.Fatalf("group create = %+v", built)
	}
	// A lost response is retried under the same id and answered from the
	// stored pending Commit, not rebuilt.
	again := commitOf(alice.must(proto.MLSGroupCreate, create))
	if again.Created || again.CommitB64 != built.CommitB64 {
		t.Fatal("a retried group create built a second Commit")
	}

	confirmed := alice.confirm(id, proto.MLSCommitOutcomeAccepted, "")
	if confirmed.Epoch != 1 || !confirmed.WelcomeReleasable {
		t.Fatalf("confirm = %+v", confirmed)
	}
	joined := bob.must(proto.MLSJoin, proto.MLSJoinRequest{
		Permit: bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv, WelcomeB64: built.WelcomeB64,
	}).Data.(proto.MLSJoinResponseData)
	if joined.Epoch != 1 {
		t.Fatalf("bob joined at epoch %d, want 1", joined.Epoch)
	}
	return &dm{alice: alice, bob: bob, seq: 1}
}

func (c *dm) nextSeq() uint64 {
	c.seq++
	return c.seq
}

func TestMLSChatE2E_ADMIsCreatedConfirmedAndJoined(t *testing.T) {
	c := newDM(t)

	// Bob's pins now hold Alice, recorded only once the join was on disk.
	if _, err := keychain.GetPeerKeyPin(c.bob.store, c.bob.id, c.alice.id); err != nil {
		t.Fatalf("bob has no pin for alice after joining: %v", err)
	}
	// A second create over the confirmed group is refused and moves nothing.
	c.alice.refused(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: c.alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{c.bob.keyPackage()},
	}, proto.ChatStateErrorCodeConflict)
}

// A KeyPackage the server hands out for Bob but which names someone else is
// refused before anything is built.
func TestMLSChatE2E_AKeyPackageForAnotherAccountIsRefused(t *testing.T) {
	e2eStateRoot(t)
	alice, bob := newKeeper(t, e2eAlice), newKeeper(t, e2eBob)
	kp := bob.keyPackage()
	kp.AccountID = "c3333333-3333-4333-8333-333333333333"
	alice.refused(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{kp},
	}, proto.ChatMLSErrorCodeLeafUntrusted)

	// Nothing was persisted: a correct create afterwards is the first one.
	created := commitOf(alice.must(proto.MLSGroupCreate, proto.MLSGroupCreateRequest{
		Permit: alice.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: alice.nextCommitID(), Members: []proto.MLSMemberKeyPackage{bob.keyPackage()},
	}))
	if !created.Created {
		t.Fatal("the refused create left a group behind")
	}
}

// Both members build against epoch 1; the server takes Alice's. Alice confirms
// accepted, Bob confirms superseded with Alice's Commit, and both are on
// epoch 2 in the same group: a Commit Bob builds next is one Alice applies.
func TestMLSChatE2E_ACommitRaceConverges(t *testing.T) {
	c := newDM(t)
	aliceCommit := c.alice.buildUpdate(1)
	bobCommit := c.bob.buildUpdate(1)

	// Until the verdict arrives neither may build again.
	c.bob.refused(proto.MLSCommitBuild, proto.MLSCommitBuildRequest{
		Permit: c.bob.permit(), OrgID: e2eOrg, ConversationID: e2eConv,
		ClientCommitID: c.bob.nextCommitID(), ExpectedEpoch: 1, UpdateSelf: true,
	}, proto.ChatMLSErrorCodeCommitPending)

	// The response to Bob was lost: unknown moves nothing and hands back the
	// Commit to ask about.
	unknown := c.bob.confirm(bobCommit.ClientCommitID, proto.MLSCommitOutcomeUnknown, "")
	if unknown.CommitB64 != bobCommit.CommitB64 || unknown.Epoch != 1 {
		t.Fatalf("unknown outcome = %+v", unknown)
	}

	won := c.alice.confirm(aliceCommit.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	lost := c.bob.confirm(bobCommit.ClientCommitID, proto.MLSCommitOutcomeSuperseded, aliceCommit.CommitB64)
	if won.Epoch != 2 || lost.Epoch != 2 || lost.WelcomeReleasable || won.WelcomeReleasable {
		t.Fatalf("after the race: alice %+v, bob %+v", won, lost)
	}
	c.nextSeq()

	next := c.bob.buildUpdate(2)
	c.bob.confirm(next.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	if got := c.alice.process(c.nextSeq(), 3, next.CommitB64); got.Epoch != 3 || got.Removed {
		t.Fatalf("alice applied bob's next commit as %+v", got)
	}
}

// Handshakes apply in epoch order. The same row again, and a row that comes
// after one not yet applied, are both refused and change nothing.
func TestMLSChatE2E_HandshakesApplyInOrder(t *testing.T) {
	c := newDM(t)
	first := c.bob.buildUpdate(1)
	c.bob.confirm(first.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	second := c.bob.buildUpdate(2)
	c.bob.confirm(second.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")

	c.alice.refused(proto.MLSProcess, c.alice.processRequest(5, 3, second.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	c.alice.process(4, 2, first.CommitB64)
	c.alice.refused(proto.MLSProcess, c.alice.processRequest(4, 2, first.CommitB64), proto.ChatMLSErrorCodeEpochStale)
	// A row that claims the right epoch but carries a Commit for another one
	// passes the ordering check and is refused by MLS, which binds the epoch
	// into the Commit. Nothing is kept.
	c.alice.refused(proto.MLSProcess, c.alice.processRequest(5, 3, first.CommitB64), proto.ChatMLSErrorCodeFailed)
	c.alice.process(5, 3, second.CommitB64)
}

// P3: Bob rotates and promotes a new leaf key. The group still signs as the old
// one until his Update carries the new key, and Alice takes that leaf as an
// entering leaf: full §5.3 checks, and her newest-declaration record for Bob
// moves to the rotated declaration.
func TestMLSChatE2E_ARotatedLeafEntersThroughUpdateSelf(t *testing.T) {
	c := newDM(t)
	before, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}

	c.bob.declare(proto.MLSLeafReasonRotate, before.NotBefore+60)
	update := c.bob.buildUpdate(1)
	c.bob.confirm(update.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 2, update.CommitB64)

	after, _, err := keychain.GetMLSLeafNewest(c.alice.store, c.alice.id, c.bob.id)
	if err != nil {
		t.Fatal(err)
	}
	if after.NotBefore != before.NotBefore+60 || after.Fingerprint == before.Fingerprint {
		t.Fatalf("alice's record for bob = %+v, was %+v; the rotated leaf did not enter", after, before)
	}

	// The group now signs as the new key on both sides: another Update from
	// Bob needs no new approval and applies.
	next := c.bob.buildUpdate(2)
	c.bob.confirm(next.ClientCommitID, proto.MLSCommitOutcomeAccepted, "")
	c.alice.process(c.nextSeq(), 3, next.CommitB64)
}
